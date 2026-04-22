package main

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID       string    `yaml:"id"`
	Name     string    `yaml:"name"`
	Severity string    `yaml:"severity"`
	Tech     []string  `yaml:"tech"`
	Requests []Request `yaml:"requests"`
}

type Request struct {
	Method   string    `yaml:"method"`
	Path     []string  `yaml:"path"`
	Payloads []string  `yaml:"payloads"`
	Matchers []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type  string   `yaml:"type"`
	Part  string   `yaml:"part"`
	Words []string `yaml:"words"`
}

func LoadTemplates(dir string) ([]Template, error) {
	var templates []Template
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" || filepath.Ext(file.Name()) == ".yml" {
			data, err := os.ReadFile(filepath.Join(dir, file.Name()))
			if err != nil {
				continue
			}

			var t Template
			if err := yaml.Unmarshal(data, &t); err != nil {
				continue
			}
			templates = append(templates, t)
		}
	}
	return templates, nil
}
