//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReadOciImageConfigJson(t *testing.T) {
	kataGuestSvmDir = "/tmp/dat1"
	containerId := "123456"
	configJson := `{"ociVersion":"1.0.0","process":{"terminal":true,"user":{"uid":0,"gid":0},"args":["nginx","-g","daemon off;"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","NGINX_VERSION=1.17.5","NJS_VERSION=0.3.6","PKG_RELEASE=1~buster"],"cwd":"/"},"root":{"path":"rootfs"},"linux":{}}`

	d1 := []byte(configJson)
	configPathrootfs := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle")
	err := os.MkdirAll(configPathrootfs, os.ModeDir)
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}

	configPath := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle", "config.json")
	_ = ioutil.WriteFile(configPath, d1, 0644)
	ociJsonSpec, err := readOciImageConfigJson(containerId)
	if ociJsonSpec.Version != "1.0.0" {
		t.Errorf("Failed to read oci image config json")
	}
	os.RemoveAll(kataGuestSvmDir)

}

func TestPersistDecryptedCM(t *testing.T) {
	kataGuestSvmDir = "/tmp/dat1"
	containerId := "123456"
	decryptedConfig := `spec:
  containers:
  - env:
    - name: DEMO_GREETING
      value: Hello from the environment
    - name: DEMO_FAREWELL
      value: Such a sweet sorrow
    image: nginx:latest
    name: nginx
    ports:
    - containerPort: 80
    resources: {}`
	decryptedConfigByte := []byte(decryptedConfig)
	err := persistDecryptedCM(containerId, decryptedConfigByte)
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	decryptFile := filepath.Join(kataGuestSvmDir, containerId, "decryptedConfig")
	dat, err := ioutil.ReadFile(decryptFile)
	res := bytes.Compare(decryptedConfigByte, dat)
	if res != 0 {
		t.Errorf("Failed reading config map")
	}
	os.RemoveAll(kataGuestSvmDir)
}

func TestPullOciImage(t *testing.T) {
	kataGuestSvmDir = "/tmp/dat1"
	containerId := "123456"
	image := "nginx"
	create_dir := filepath.Join(kataGuestSvmDir, containerId, "rootfs_dir")
	destRefString := skopeoDestImageTransport + create_dir

	testSkopeoCopy(t, image, containerId)

	// Three files should get created: blobs, index.json, oci-layout
	files, _ := ioutil.ReadDir(create_dir)
	if len(files) != 3 {
		t.Errorf("Skopeo copy failed copying oci images to %s", destRefString)
	}
	os.RemoveAll(kataGuestSvmDir)
}

func TestIsPauseContainer(t *testing.T) {
	args := []string{"pause", "nginx"}
	check := IsPauseContainer(args)
	if check {
		t.Errorf("Failed to identify a pause container")
	}
}

func testSkopeoCopy(t *testing.T, image string, containerId string) {

	_, err := exec.LookPath("skopeo")
	if err != nil {
		t.Skip("Skipping test as skopeo binary not present")
	}

	err = pullOciImage(image, containerId)
	if err != nil {
		t.Errorf("Error exeuting skopeo copy to pull oci image: %v", err)
	}

}
func TestCreateRuntimeBundle(t *testing.T) {
	kataGuestSvmDir = "/tmp/dat1"
	containerId := "123456"
	image := "nginx"
	ociBundle := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle")
	testSkopeoCopy(t, image, containerId)
	err := createRuntimeBundle(containerId)
	if err != nil {
		t.Errorf("Error creating runtime bundle: %v", err)
	}

	files, _ := ioutil.ReadDir(ociBundle)
	//Two files should get created: config.json,  rootfs
	if len(files) != 2 {
		t.Errorf("Failed to create runtime bundle at %s", ociBundle)
	}
	os.RemoveAll(kataGuestSvmDir)

}
