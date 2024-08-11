package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8yaml "k8s.io/apimachinery/pkg/util/yaml"
)

func listFiles(root string) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return files, err
	}

	return files, nil
}

func readFilesAsManifests(paths []string) (result []unstructured.Unstructured, errs []error) {
	for _, path := range paths {
		rawdata, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not read file: %s from disk: %s", path, err))
		}
		manifest, err := readManifestData(bytes.NewReader(rawdata))
		if err != nil {
			errs = append(errs, fmt.Errorf("could not read file: %s from disk: %s", path, err))
		}
		result = append(result, manifest...)
	}

	return result, errs
}

func readManifestData(yamlData io.Reader) ([]unstructured.Unstructured, error) {
	decoder := k8yaml.NewYAMLOrJSONDecoder(yamlData, 1)

	var manifests []unstructured.Unstructured
	for {
		nxtManifest := unstructured.Unstructured{}
		err := decoder.Decode(&nxtManifest)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		// Skip empty manifests
		if len(nxtManifest.Object) > 0 {
			manifests = append(manifests, nxtManifest)
		}
	}

	return manifests, nil
}

// https://github.com/go-git/go-git/issues/74#issuecomment-647779420
func detectGitPath(path string) (string, error) {
	// normalize the path
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	for {
		fi, err := os.Stat(filepath.Join(path, ".git"))
		if err == nil {
			if !fi.IsDir() {
				return "", fmt.Errorf(".git exist but is not a directory")
			}
			return filepath.Join(path, ".git"), nil
		}
		if !os.IsNotExist(err) {
			// unknown error
			return "", err
		}

		// detect bare repo
		ok, err := isGitDir(path)
		if err != nil {
			return "", err
		}
		if ok {
			return path, nil
		}

		if parent := filepath.Dir(path); parent == path {
			return "", fmt.Errorf(".git not found")
		} else {
			path = parent
		}
	}
}

func isGitDir(path string) (bool, error) {
	markers := []string{"HEAD", "objects", "refs"}

	for _, marker := range markers {
		_, err := os.Stat(filepath.Join(path, marker))
		if err == nil {
			continue
		}
		if !os.IsNotExist(err) {
			// unknown error
			return false, err
		} else {
			return false, nil
		}
	}

	return true, nil
}
