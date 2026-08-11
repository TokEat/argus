package db

import (
	"encoding/json"

	pb "github.com/user/dddd-proto/go/scan"
)

func SubTaskToProto(task *SubTask) (*pb.Task, error) {
	var targets []string
	if task.ChunkTargets != "" {
		if err := json.Unmarshal([]byte(task.ChunkTargets), &targets); err != nil {
			return nil, err
		}
	}

	config := []byte("{}")
	if task.Config != "" {
		config = []byte(task.Config)
	}

	return &pb.Task{
		TaskId:     task.ID,
		Targets:    targets,
		Config:     config,
		Priority:   int32(task.Priority),
		TimeoutSec: int32(task.TimeoutSec),
	}, nil
}
