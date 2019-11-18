//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	b64 "encoding/base64"
	"errors"
	"github.com/kata-containers/agent/crypto"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	agentName                = "kata-agent"
	configmapFileName        = "kavach.properties"
	configmapJsonFileName    = "config.json"
	kataGuestSharedDir       = "/run/kata-containers/shared/containers"
	skopeoSrcImageTransport  = "docker://" //Todo: Handle other registries as well
	skopeoDestImageTransport = "oci:"
	configmapMountPoint      = "/etc/kavach"
)

var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var agentLog = logrus.WithFields(agentFields)
var svmConfig SVMConfig
var OciJsonSpec = &specs.Spec{}
var kataGuestSvmDir = "/run/svm"

type SVMConfig struct {
	Spec Spec `yaml:"spec"`
}
type Requests struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}
type Resources struct {
	Requests Requests `yaml:"requests"`
}
type Env struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
type Ports struct {
	ContainerPort int `yaml:"containerPort"`
}
type Containers struct {
	Name      string    `yaml:"name"`
	Image     string    `yaml:"image"`
	Resources Resources `yaml:"resources"`
	Args      []string  `yaml:"args"`
	Env       []Env     `yaml:"env"`
	Cwd       string    `yaml:"cwd"`
	Ports     []Ports   `yaml:"ports"`
}
type Spec struct {
	Containers []Containers `yaml:"containers"`
}

//IsPauseContainer checks if it is pause container
func IsPauseContainer(args []string) bool {

	pause_args := "/pause"

	if len(args) == 1 && pause_args == args[0] {
		agentLog.Debug("It is a pause image")
		return true
	}
	return false
}

//StartSecureContainers starts a secure container from an encrypted configmap inside a Kata VM
func StartSecureContainers(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	err := readEncryptedConfigmap(req, ociSpec.Process.Env)
	if err != nil {
		agentLog.WithError(err).Errorf("readEncryptedConfigmap errored out: %s", err)
		return err
	}

	err = pullOciImage(ociSpec, svmConfig, req)
	if err != nil {
		agentLog.WithError(err).Errorf("pullSecureImage errored out: %s", err)
		return err
	}

	err = createRuntimeBundle(ociSpec, req)
	if err != nil {
		agentLog.WithError(err).Errorf("createRuntimeBundle errored out: %s", err)
		return err
	}

	updateOCIReq(ociSpec, req, svmConfig)

	ociBundle := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_bundle")
	ociSpec.Root.Path = filepath.Join(ociBundle, "rootfs")

	return nil
}

//Read encrypted configmap volume mounted into the scratch image.
func readEncryptedConfigmap(req *pb.CreateContainerRequest, vaultEnv []string) error {

	var file string

	agentLog.Debug("Reading encrypted configmap for container:", req.ContainerId)
	for _, mounts := range req.OCI.Mounts {
		if mounts.Destination == configmapMountPoint {
			file = filepath.Join(mounts.Source, configmapFileName)
			agentLog.Debug("Found encrypted configmap at:", mounts.Source)
			break
		}
	}

	if len(file) == 0 {
		err := errors.New("No encrypted configmap found")
		agentLog.WithError(err).Errorf("Error finding configmap")
		return err
	}

	err := fileExists(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for %s", file)
		return err
	}

	agentLog.WithField("ConfigMap path: ", file).Debug("Found file for reading config map")
	yamlContainerSpec, err := ioutil.ReadFile(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not read file %s: %s", file, err)
		return err
	}

	containerspec, err := b64.StdEncoding.DecodeString(string(yamlContainerSpec)) //decoded into an encoded blob
	if err != nil {
		return err
	}

	key, nonce, err := crypto.GetCMDecryptionKey(vaultEnv)
	if err != nil {
		return err
	}

	decryptedConfig, err := crypto.DecryptSVMConfig(containerspec, key, nonce)
	if err != nil {
		return err
	}

	err = persistDecryptedCM(req.ContainerId, decryptedConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error when persisting decrypted configmap %s", err)
		return err
	}

	err = yaml.Unmarshal(decryptedConfig, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml %s", err)
		return err
	}

	return err

}

func createOCIRuntimeBundle(ociImage string, ociBundle string) error {

	agentLog.Debug("Executing oci-image-tool to create OCI runtime bundle")
	args := []string{"create", "--ref=platform.os=linux", ociImage, ociBundle}
	err := execCommand("oci-image-tool", args)
	if err != nil {
		agentLog.WithField("ocibundle err: ", err).Debug("create oci bundle failed")
		return err
	}

	err = fileExists(ociBundle)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for ociBundle: %s", ociBundle)
	}

	return err
}

func makeOCIBundleExecutable(ociBundle string) error {

	agentLog.Debug("Executing chmod to make ociBundle executable")
	args := []string{"-R", "+x", ociBundle}
	err := execCommand("chmod", args)
	if err != nil {
		agentLog.WithError(err).Errorf("Failed to make OCI BUndle executable %s", err)
	}
	return err
}

func createRuntimeBundle(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	ociBundle := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_bundle")
	ociImage := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_dir")

	agentLog.WithField("rootfs_dir is: ", ociImage).Debug("Path to ociImage")
	agentLog.WithField("rootfs_bundle is: ", ociBundle).Debug("Path to ociBundle")
	agentLog.Debug("Create runtime bundle for container id:", req.ContainerId)

	// Since image.CreateRuntimeBundleLayout is returning a nil pointer exception, os exec the oci-image-tool directly
	err := createOCIRuntimeBundle(ociImage, ociBundle)
	if err != nil {
		return err
	}
	agentLog.WithField("ociBundle: ", ociBundle).Debug("Created ociBundle successfully")

	// Make ociBundle executable as some images need to execute .sh files at startup
	err = makeOCIBundleExecutable(ociBundle)
	if err != nil {
		return err
	}
	agentLog.WithField("ociBundle: ", ociBundle).Debug("Made ociBundle executable")
	return err
}

func persistDecryptedCM(containerId string, decryptedConfig []byte) error {

	decryptCMDir := filepath.Join(kataGuestSvmDir, containerId)
	decryptCMFile := filepath.Join(decryptCMDir, "decryptedConfig")

	agentLog.Debug("Create directory to write decrypted configmap into: ", decryptCMDir)
	err := os.MkdirAll(decryptCMDir, os.ModeDir)
	if err != nil {
		return err
	}

	agentLog.Debug("Write decrypted configmap into: ", decryptCMFile)
	err = ioutil.WriteFile(decryptCMFile, decryptedConfig, 0644)
	return err
}

func execCommand(binary string, args []string) error {

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err
}

func pullOciImage(ociSpec *specs.Spec, svmConfig SVMConfig, req *pb.CreateContainerRequest) error {

	pull := skopeoSrcImageTransport + svmConfig.Spec.Containers[0].Image
	create_dir := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_dir:latest")
	destRefString := skopeoDestImageTransport + create_dir

	err := os.MkdirAll(create_dir, os.ModeDir)
	if err != nil {
		agentLog.WithError(err).Errorf("Error creating directory %s %s", create_dir, err)
		return err
	}

	agentLog.Debug("Executing skopeo copy for containerId ", req.ContainerId)
	args := []string{"copy", pull, destRefString}
	err = execCommand("skopeo", args)
	if err != nil {
		agentLog.WithError(err).Errorf("Error executing skopeo copy %s", err)
	}

	return err
}

func UpdateExecProcessConfig(containerId string, processEnv []string, processCwd string) ([]string, string, error) {
	decryptedConfig := filepath.Join(kataGuestSvmDir, containerId, "decryptedConfig")
	data, err := ioutil.ReadFile(decryptedConfig)
	err = yaml.Unmarshal(data, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml while execing inside container %s", err)
		return processEnv, processCwd, err
	}

	OciJsonSpec, err = readOciImageConfigJson(containerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readConfigJson errored out: %s", err)
		return processEnv, processCwd, err
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		processEnv = UpdateEnv(processEnv, OciJsonSpec.Process.Env, svmConfig)
	}

	processCwd = UpdateCwd(processCwd, OciJsonSpec.Process.Cwd, svmConfig)
	OciJsonSpec = &specs.Spec{}
	svmConfig = SVMConfig{}
	return processEnv, processCwd, nil
}

func fileExists(path string) error {

	var err error
	if _, err := os.Stat(path); os.IsNotExist(err) {
		agentLog.Debug("File does not exist", path)
	} else if err != nil {
		agentLog.Debug("File may or may not exist", path)
	}
	return err
}

func readOciImageConfigJson(containerId string) (*specs.Spec, error) {

	configPath := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle", "config.json")
	agentLog.Debug("Reading configJSONBytes from", configPath)

	err := fileExists(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("Error when looking for configPath %s", configPath)
		return OciJsonSpec, err
	}

	configJSONBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not open OCI config file %s", configPath)
		return OciJsonSpec, err
	}

	agentLog.Debug("Unmarshalling the config json data from ", configPath)
	if err := json.Unmarshal(configJSONBytes, &OciJsonSpec); err != nil {
		agentLog.WithError(err).Errorf("Could not unmarshall OCI config file")
		return OciJsonSpec, err
	}

	return OciJsonSpec, nil
}

//UpdateEnv updates the exec process's environment variables
func UpdateEnv(ociEnv []string, ociJsonEnv []string, svmConfig SVMConfig) []string {
	ociEnv = append(ociEnv, ociJsonEnv...)
	for i := 0; i < len(svmConfig.Spec.Containers[0].Env); i++ {
		createEnv := svmConfig.Spec.Containers[0].Env[i].Name + "=" + svmConfig.Spec.Containers[0].Env[i].Value
		ociEnv = append(ociEnv, createEnv)
	}
	return ociEnv
}

//UpdateCwd to update the current working directory of the exec process
func UpdateCwd(ociCwd string, ociJsonCwd string, svmConfig SVMConfig) string {
	if svmConfig.Spec.Containers[0].Cwd != "" {
		ociCwd = svmConfig.Spec.Containers[0].Cwd
	} else {
		ociCwd = ociJsonCwd
	}
	return ociCwd
}

func updateOCIReq(ociSpec *specs.Spec, req *pb.CreateContainerRequest, svmConfig SVMConfig) {

	OciJsonSpec, err := readOciImageConfigJson(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readOciImageConfigJson Errored out: %s", err)
	}

	// Give higher priority to args specified in the pod yaml in CM than json spec of the image
	if len(svmConfig.Spec.Containers[0].Args) == 0 {
		req.OCI.Process.Args = OciJsonSpec.Process.Args
	} else {
		req.OCI.Process.Args = svmConfig.Spec.Containers[0].Args
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		req.OCI.Process.Env = UpdateEnv(req.OCI.Process.Env, OciJsonSpec.Process.Env, svmConfig)
	}

	req.OCI.Process.Cwd = UpdateCwd(req.OCI.Process.Cwd, OciJsonSpec.Process.Cwd, svmConfig)

}
