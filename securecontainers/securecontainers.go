//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

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
	//TODO: Handle infra pod incase of openshift
	pause_args := "/pause"

	if len(args) == 1 && pause_args == args[0] {
		agentLog.Debug("It is a pause image")
		return true
	}
	return false
}

//UpdateSecureContainersOCIReq updates the OCI Request for a secure container from an encrypted configmap inside Kata VM
func UpdateSecureContainersOCIReq(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	svmConfig, err := readEncryptedConfigmap(req, ociSpec.Process.Env)
	if err != nil {
		agentLog.WithError(err).Errorf("readEncryptedConfigmap errored out: %s", err)
		return err
	}

	err = pullOciImage(svmConfig.Spec.Containers[0].Image, req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("pullSecureImage errored out: %s", err)
		return err
	}

	err = createRuntimeBundle(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("createRuntimeBundle errored out: %s", err)
		return err
	}

	err = updateOCIReq(req, *svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("updating OCI Request errored out: %s", err)
		return err
	}

	ociSpec.Root.Path = filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_bundle", "rootfs")

	return nil
}

//Read encrypted configmap volume mounted into the scratch image.
func readEncryptedConfigmap(req *pb.CreateContainerRequest, vaultEnv []string) (*SVMConfig, error) {

	var svmConfig SVMConfig
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
		return nil, err
	}

	err := fileExists(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for %s", file)
		return nil, err
	}

	agentLog.WithField("ConfigMap path: ", file).Debug("Found file for reading config map")
	encryptedYamlContainerSpec, err := ioutil.ReadFile(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not read file %s: %s", file, err)
		return nil, err
	}

	containerspec, err := b64.StdEncoding.DecodeString(string(encryptedYamlContainerSpec)) //decoded into an encoded blob
	if err != nil {
		return nil, err
	}

	key, nonce, err := crypto.GetCMDecryptionKey(vaultEnv)
	if err != nil {
		return nil, err
	}

	decryptedConfig, err := crypto.DecryptSVMConfig(containerspec, key, nonce)
	if err != nil {
		return nil, err
	}

	err = persistDecryptedCM(req.ContainerId, decryptedConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error when persisting decrypted configmap %s", err)
		return nil, err
	}

	err = yaml.Unmarshal(decryptedConfig, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml %s", err)
		return nil, err
	}

	return &svmConfig, err

}

func createOCIRuntimeBundle(ociImage string, ociBundle string) error {

	agentLog.Debug("Executing oci-image-tool to create OCI runtime bundle")
	args := []string{"create", "--ref=platform.os=linux", ociImage, ociBundle}
	err, errStr := execCommand("oci-image-tool", args)
	if err != nil {
		agentLog.WithField("ocibundle err: ", err).Debug("create oci bundle failed:", errStr)
		return err
	} else {
		agentLog.Debug("Executed command oci-image-tool successfully:", errStr)
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
	err, errStr := execCommand("chmod", args)
	if err != nil {
		agentLog.WithError(err).Errorf("Failed to make OCI BUndle executable %s", errStr)
	} else {
		agentLog.Debug("Executed command chmod successfully", errStr)
	}
	return err
}

func createRuntimeBundle(containerId string) error {

	ociBundle := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle")
	ociImage := filepath.Join(kataGuestSvmDir, containerId, "rootfs_dir")

	agentLog.WithField("rootfs_dir is: ", ociImage).Debug("Path to ociImage")
	agentLog.WithField("rootfs_bundle is: ", ociBundle).Debug("Path to ociBundle")
	agentLog.Debug("Create runtime bundle for container id:", containerId)

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

func execCommand(binary string, args []string) (error, string) {

	var out bytes.Buffer
	var stderr bytes.Buffer
	var errString string
	cmd := exec.Command(binary, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		errString = stderr.String()
	} else {
		errString = out.String()
	}
	return err, errString
}

func pullOciImage(image string, containerId string) error {

	pull := skopeoSrcImageTransport + image
	createDir := filepath.Join(kataGuestSvmDir, containerId, "rootfs_dir:latest")
	destRefString := skopeoDestImageTransport + createDir

	err := os.MkdirAll(createDir, os.ModeDir)
	if err != nil {
		agentLog.WithError(err).Errorf("Error creating directory %s %s", createDir, err)
		return err
	}

	//ToDo: Add skopeo copy with authorization and via API.
	agentLog.Debug("Executing skopeo copy for containerId ", containerId)
	args := []string{"copy", pull, destRefString}
	err, errStr := execCommand("skopeo", args)
	if err != nil {
		agentLog.WithError(err).Errorf("Error executing skopeo copy %s", errStr)
	} else {
		agentLog.Debug("Executed skopeo successfully:", errStr)
	}

	return nil
}

func UpdateExecProcessConfig(containerId string, processEnv []string, processCwd string) ([]string, string, error) {

	var svmConfig SVMConfig
	decryptedConfig := filepath.Join(kataGuestSvmDir, containerId, "decryptedConfig")
	data, err := ioutil.ReadFile(decryptedConfig)
	err = yaml.Unmarshal(data, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml while execing inside container %s", err)
		return processEnv, processCwd, err
	}

	ociJsonSpec, err := readOciImageConfigJson(containerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readConfigJson errored out: %s", err)
		return processEnv, processCwd, err
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		processEnv = updateEnv(processEnv, ociJsonSpec.Process.Env, svmConfig)
	}

	processCwd = updateCwd(processCwd, ociJsonSpec.Process.Cwd, svmConfig.Spec.Containers[0].Cwd, svmConfig)
	return processEnv, processCwd, nil
}

func fileExists(path string) error {

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("File does not exist")
	} else if err != nil {
		return errors.New("File may or may not exist")
	}
	return nil
}

func readOciImageConfigJson(containerId string) (*specs.Spec, error) {

	var ociJsonSpec = &specs.Spec{}
	configPath := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle", "config.json")
	agentLog.Debug("Reading configJSONBytes from", configPath)

	configJSONBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not open OCI config file %s", configPath)
		return ociJsonSpec, err
	}

	agentLog.Debug("Unmarshalling the config json data from ", configPath)
	if err := json.Unmarshal(configJSONBytes, &ociJsonSpec); err != nil {
		agentLog.WithError(err).Errorf("Could not unmarshall OCI config file")
		return ociJsonSpec, err
	}

	return ociJsonSpec, nil
}

func updateEnv(ociEnv []string, ociJsonEnv []string, svmConfig SVMConfig) []string {
	ociEnv = append(ociEnv, ociJsonEnv...)
	for i := 0; i < len(svmConfig.Spec.Containers[0].Env); i++ {
		createEnv := svmConfig.Spec.Containers[0].Env[i].Name + "=" + svmConfig.Spec.Containers[0].Env[i].Value
		ociEnv = append(ociEnv, createEnv)
	}
	return ociEnv
}

func updateCwd(ociCwd string, ociJsonCwd string, svmConfigCwd string, svmConfig SVMConfig) string {
	if svmConfig.Spec.Containers[0].Cwd != "" {
		ociCwd = svmConfigCwd
	} else {
		ociCwd = ociJsonCwd
	}
	return ociCwd
}

func updateOCIReq(req *pb.CreateContainerRequest, svmConfig SVMConfig) error {

	ociJsonSpec, err := readOciImageConfigJson(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readOciImageConfigJson Errored out: %s", err)
		return err
	}

	// Give higher priority to args specified in the pod yaml in CM than json spec of the image
	if len(svmConfig.Spec.Containers[0].Args) == 0 {
		req.OCI.Process.Args = ociJsonSpec.Process.Args
	} else {
		req.OCI.Process.Args = svmConfig.Spec.Containers[0].Args
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		req.OCI.Process.Env = updateEnv(req.OCI.Process.Env, ociJsonSpec.Process.Env, svmConfig)
	}

	req.OCI.Process.Cwd = updateCwd(req.OCI.Process.Cwd, ociJsonSpec.Process.Cwd, svmConfig.Spec.Containers[0].Cwd, svmConfig)
	return nil
}
