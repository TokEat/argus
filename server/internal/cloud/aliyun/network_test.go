package aliyun

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

func TestAutoCreateNetworkVSwitchSelection(t *testing.T) {
	const supportedZones = `[{"ZoneId":"cn-test-a","AvailableResourceCreation":{"ResourceTypes":["VSwitch"]}},{"ZoneId":"cn-test-b","AvailableResourceCreation":{"ResourceTypes":["VSwitch"]}}]`
	tests := []struct {
		name        string
		zones       string
		existing    bool
		firstError  string
		allDisabled bool
		emptyCreate bool
		wantZones   []string
		wantError   string
	}{
		{name: "reuse existing switch", existing: true},
		{name: "skip unsupported zone", zones: `[{"ZoneId":"cn-test-a","AvailableResourceCreation":{"ResourceTypes":["Instance"]}},{"ZoneId":"cn-test-b","AvailableResourceCreation":{"ResourceTypes":["VSwitch"]}}]`, wantZones: []string{"cn-test-b"}},
		{name: "disabled zone fallback", zones: supportedZones, firstError: "OperationDenied.ZoneIsDisabled", wantZones: []string{"cn-test-a", "cn-test-b"}},
		{name: "permission error stops", zones: supportedZones, firstError: "Forbidden.RAM", wantZones: []string{"cn-test-a"}, wantError: "Forbidden.RAM"},
		{name: "CIDR error stops", zones: supportedZones, firstError: "InvalidCidrBlock.Overlap", wantZones: []string{"cn-test-a"}, wantError: "InvalidCidrBlock.Overlap"},
		{name: "all zones disabled", zones: supportedZones, allDisabled: true, wantZones: []string{"cn-test-a", "cn-test-b"}, wantError: "OperationDenied.ZoneIsDisabled"},
		{name: "no supported zones", zones: `[{"ZoneId":"cn-test-a","AvailableResourceCreation":{"ResourceTypes":[]}}]`, wantError: "没有支持创建交换机的可用区"},
		{name: "missing zone list", zones: `[]`, wantError: "没有支持创建交换机的可用区"},
		{name: "unknown capabilities remain compatible", zones: `[{"ZoneId":"cn-test-a"}]`, wantZones: []string{"cn-test-a"}},
		{name: "prefer advertised capabilities", zones: `[{"ZoneId":"cn-test-a"},{"ZoneId":"cn-test-b","AvailableResourceCreation":{"ResourceTypes":["VSwitch"]}}]`, wantZones: []string{"cn-test-b"}},
		{name: "ignore malformed and duplicate zones", zones: `[null,{},{"ZoneId":""},{"ZoneId":"cn-test-a"},{"ZoneId":"cn-test-a"}]`, allDisabled: true, wantZones: []string{"cn-test-a"}, wantError: "OperationDenied.ZoneIsDisabled"},
		{name: "ambiguous create response stops", zones: supportedZones, emptyCreate: true, wantZones: []string{"cn-test-a"}, wantError: "未返回交换机 ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempted []string
			zoneQueries, securityGroupCreates := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse ECS request: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				write := func(body string) { _, _ = w.Write([]byte(body)) }
				action := r.Header.Get("x-acs-action")
				switch action {
				case "DescribeVpcs":
					write(`{"Vpcs":{"Vpc":[{"VpcId":"vpc-test","Status":"Available"}]}}`)
				case "DescribeVSwitches":
					if tt.existing || r.FormValue("VSwitchId") != "" {
						write(`{"VSwitches":{"VSwitch":[{"VSwitchId":"vsw-test","Status":"Available"}]}}`)
					} else {
						write(`{"VSwitches":{"VSwitch":[]}}`)
					}
				case "DescribeZones":
					zoneQueries++
					write(`{"Zones":{"Zone":` + tt.zones + `}}`)
				case "CreateVSwitch":
					if r.FormValue("RegionId") != "cn-test" || r.FormValue("VpcId") != "vpc-test" || r.FormValue("CidrBlock") != "10.0.1.0/24" {
						t.Error("fallback changed the requested region, VPC or CIDR")
					}
					attempted = append(attempted, r.FormValue("ZoneId"))
					code := ""
					if len(attempted) == 1 {
						code = tt.firstError
					}
					if tt.allDisabled {
						code = "OperationDenied.ZoneIsDisabled"
					}
					if code != "" {
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(map[string]string{"Code": code, "Message": "synthetic ECS error"})
					} else if tt.emptyCreate {
						write(`{}`)
					} else {
						write(`{"VSwitchId":"vsw-test"}`)
					}
				case "DescribeSecurityGroups":
					write(`{"SecurityGroups":{"SecurityGroup":[]}}`)
				case "CreateSecurityGroup":
					securityGroupCreates++
					if r.FormValue("VpcId") != "vpc-test" {
						t.Error("security group VPC changed")
					}
					write(`{"SecurityGroupId":"sg-test"}`)
				default:
					t.Errorf("unexpected ECS action %q", action)
					w.WriteHeader(http.StatusBadRequest)
					write(`{"Code":"UnexpectedAction","Message":"test does not allow this action"}`)
				}
			}))
			defer server.Close()
			client, err := ecs.NewClient(&openapi.Config{
				AccessKeyId: tea.String("test-key"), AccessKeySecret: tea.String("test-secret"),
				Endpoint: tea.String(strings.TrimPrefix(server.URL, "http://")), Protocol: tea.String("http"),
			})
			if err != nil {
				t.Fatal(err)
			}
			provider := &ECSProvider{client: client, regionId: "cn-test"}
			sg, vsw, err := provider.AutoCreateNetwork()
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				if securityGroupCreates != 0 {
					t.Error("network error must stop before creating security groups")
				}
			} else if err != nil || sg != "sg-test" || vsw != "vsw-test" || securityGroupCreates != 1 {
				t.Fatalf("network result = (%q, %q, %v), security group creates = %d", sg, vsw, err, securityGroupCreates)
			}
			if !reflect.DeepEqual(attempted, tt.wantZones) {
				t.Errorf("attempted zones = %v, want %v", attempted, tt.wantZones)
			}
			if tt.existing && zoneQueries != 0 {
				t.Error("existing switch must not trigger zone discovery")
			}
		})
	}
}
