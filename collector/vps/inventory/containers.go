package inventory

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type Container struct {
	ID           string   `json:"id"`
	ImageID      string   `json:"image_id"`
	State        string   `json:"state"`
	Digests      []string `json:"digests"`
	DigestStatus string   `json:"digest_status"`
}

var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var imageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var repoDigest = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$`)

func collectContainers(o *Observation, run func(string, ...string) ([]byte, error)) {
	data, err := run("docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		failDocker(o, err, data)
		return
	}
	ids := strings.Fields(string(data))
	if len(ids) > 128 {
		o.Status = "error"
		o.ErrorCode = "container_limit"
		return
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !hexID.MatchString(id) || seen[id] {
			invalid(o)
			return
		}
		seen[id] = true
	}
	if len(ids) == 0 {
		o.Status = "ok"
		o.Value = []Container{}
		return
	}
	args := []string{"inspect", "--type", "container", "--format", "{{.Id}}\t{{.Image}}\t{{.State.Status}}"}
	args = append(args, ids...)
	data, err = run("docker", args...)
	if err != nil {
		failDocker(o, err, data)
		return
	}
	items := []Container{}
	images := map[string][]string{}
	seenRows := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || !seen[f[0]] || seenRows[f[0]] || !imageID.MatchString(f[1]) {
			invalid(o)
			return
		}
		switch f[2] {
		case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		default:
			invalid(o)
			return
		}
		seenRows[f[0]] = true
		images[f[1]] = nil
		items = append(items, Container{ID: f[0], ImageID: f[1], State: f[2], Digests: []string{}, DigestStatus: "unavailable"})
	}
	if len(items) != len(ids) {
		invalid(o)
		return
	}
	imageIDs := make([]string, 0, len(images))
	for id := range images {
		imageIDs = append(imageIDs, id)
	}
	sort.Strings(imageIDs)
	args = []string{"image", "inspect", "--format", "{{.Id}}\t{{json .RepoDigests}}"}
	args = append(args, imageIDs...)
	data, err = run("docker", args...)
	if err != nil {
		failDocker(o, err, data)
		o.Status = "partial"
		if o.ErrorCode == "command_failed" {
			o.ErrorCode = "image_inspect_failed"
		}
		o.Value = items
		return
	}
	seenImages := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		id, raw, ok := strings.Cut(line, "\t")
		if _, exists := images[id]; !ok || !exists || seenImages[id] {
			invalid(o)
			return
		}
		var digests []string
		if json.Unmarshal([]byte(raw), &digests) != nil {
			invalid(o)
			return
		}
		for _, d := range digests {
			if !repoDigest.MatchString(d) {
				invalid(o)
				return
			}
		}
		sort.Strings(digests)
		images[id] = digests
		seenImages[id] = true
	}
	if len(seenImages) != len(imageIDs) {
		invalid(o)
		return
	}
	for i := range items {
		if len(images[items[i].ImageID]) > 0 {
			items[i].Digests = images[items[i].ImageID]
			items[i].DigestStatus = "ok"
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	o.Status = "ok"
	for _, item := range items {
		if item.DigestStatus != "ok" {
			o.Status = "partial"
			o.ErrorCode = "image_digest_unavailable"
		}
	}
	o.Value = items
}

// Docker reports socket access failures as a normal exit status rather than
// fs.ErrPermission. Only known connection failure phrases become safe codes.
// The captured output is never included in an observation or returned error.
func failDocker(o *Observation, err error, output []byte) {
	fail(o, err)
	if o.ErrorCode != "command_failed" {
		return
	}
	text := strings.ToLower(string(output))
	if strings.Contains(text, "permission denied while trying to connect to the docker daemon socket") ||
		(strings.Contains(text, "dial unix") && strings.Contains(text, "connect: permission denied")) {
		o.Status, o.ErrorCode = "permission_denied", "permission_denied"
	} else if strings.Contains(text, "cannot connect to the docker daemon") {
		o.Status, o.ErrorCode = "unavailable", "docker_daemon_unavailable"
	}
}
