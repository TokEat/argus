package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type S3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

type S3Store struct {
	client *s3.Client
	bucket string
}

func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.Region = strings.TrimSpace(cfg.Region)
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, errors.New("EXP S3 endpoint, bucket, access key and secret key are required")
	}
	if !strings.HasPrefix(cfg.Endpoint, "http://") && !strings.HasPrefix(cfg.Endpoint, "https://") {
		scheme := "http://"
		if cfg.UseSSL {
			scheme = "https://"
		}
		cfg.Endpoint = scheme + cfg.Endpoint
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("load EXP S3 config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.EndpointResolver = s3.EndpointResolverFromURL(cfg.Endpoint)
		options.UsePathStyle = true
	})
	store := &S3Store{client: client, bucket: cfg.Bucket}
	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
		return nil, fmt.Errorf("EXP S3 bucket %q unavailable: %w", cfg.Bucket, err)
	}
	return store, nil
}

func (s *S3Store) Put(ctx context.Context, key string, r io.Reader) (Object, error) {
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return Object{}, err
	}
	output, err := s.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(cleanKey), Body: r})
	if err != nil {
		return Object{}, err
	}
	_ = output
	obj, ok, err := s.Exists(ctx, cleanKey)
	if err != nil {
		return Object{}, err
	}
	if !ok {
		return Object{}, errors.New("EXP S3 object missing after upload")
	}
	return obj, nil
}

func (s *S3Store) Open(ctx context.Context, key string) (io.ReadCloser, Object, error) {
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return nil, Object{}, err
	}
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(cleanKey)})
	if err != nil {
		return nil, Object{}, err
	}
	modTime := time.Time{}
	if output.LastModified != nil {
		modTime = *output.LastModified
	}
	return output.Body, Object{Key: cleanKey, Size: output.ContentLength, ModTime: modTime, Backend: "s3"}, nil
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]Object, error) {
	cleanPrefix, err := cleanObjectKey(prefix, true)
	if err != nil {
		return nil, err
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(cleanPrefix)})
	objects := make([]Object, 0)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Contents {
			modTime := time.Time{}
			if item.LastModified != nil {
				modTime = *item.LastModified
			}
			objects = append(objects, Object{Key: aws.ToString(item.Key), Size: item.Size, ModTime: modTime, Backend: "s3"})
		}
	}
	return objects, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(cleanKey)})
	return err
}

func (s *S3Store) Exists(ctx context.Context, key string) (Object, bool, error) {
	cleanKey, err := cleanObjectKey(key, false)
	if err != nil {
		return Object{}, false, err
	}
	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(cleanKey)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey") {
			return Object{}, false, nil
		}
		return Object{}, false, err
	}
	modTime := time.Time{}
	if output.LastModified != nil {
		modTime = *output.LastModified
	}
	return Object{Key: cleanKey, Size: output.ContentLength, ModTime: modTime, Backend: "s3"}, true, nil
}
