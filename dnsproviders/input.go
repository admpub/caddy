package dnsproviders

import (
	"sort"
	"strconv"
)

type Option struct {
	Value   string
	Text    string
	Checked bool
}

type Input struct {
	Type        string // text / textarea / radio / checkbox / select
	Name        string
	Label       string
	Value       string
	Options     []Option
	Placeholder string
	Help        string
	Required    bool
	Pattern     string // 正则表达式(首尾不要含^和$)
	MinLength   *int
	MaxLength   *int
	Min         *int
	Max         *int
	Step        *int
	Default     string
}

func (i Input) RenderHTMLHelp() string {
	if i.Help == "" {
		return ``
	}
	return `<p class="help-block">` + i.Help + `</p>`
}

func (i Input) BuildHTMLAttrs() string {
	var attrs string
	if i.Required {
		attrs += ` required`
	}
	if i.Pattern != "" {
		attrs += ` pattern="` + i.Pattern + `"`
	}
	if i.Placeholder != "" {
		attrs += ` placeholder="` + i.Placeholder + `"`
	}
	if i.MinLength != nil {
		attrs += ` minlength="` + strconv.Itoa(*i.MinLength) + `"`
	}
	if i.MaxLength != nil {
		attrs += ` maxlength="` + strconv.Itoa(*i.MaxLength) + `"`
	}
	if i.Min != nil {
		attrs += ` min="` + strconv.Itoa(*i.Min) + `"`
	}
	if i.Max != nil {
		attrs += ` max="` + strconv.Itoa(*i.Max) + `"`
	}
	if i.Step != nil {
		attrs += ` step="` + strconv.Itoa(*i.Step) + `"`
	}
	return attrs
}

func (i Input) RenderHTMLInput(namePrefix string) string {
	value := i.Value
	if len(value) == 0 && len(i.Default) > 0 {
		value = i.Default
	}
	switch i.Type {
	case `select`:
		var options string
		for _, option := range i.Options {
			options += `<option value="` + option.Value + `"`
			if option.Checked || option.Value == value {
				options += ` selected`
			}
			options += `>` + option.Text + `</option>`
		}
		return `<select class="form-control" name="` + namePrefix + i.Name + `"` + i.BuildHTMLAttrs() + `>` + options + `</select>`
	case `textarea`:
		return `<textarea class="form-control" name="` + namePrefix + i.Name + `"` + i.BuildHTMLAttrs() + `>` + value + `</textarea>`
	case `checkbox`:
		var options string
		for _, option := range i.Options {
			options += `<label><input type="checkbox" name="` + namePrefix + i.Name + `[]" value="` + option.Value + `"`
			if option.Checked || option.Value == value {
				options += ` checked`
			}
			options += `>` + option.Text + `</label>`
		}
		return options
	case `radio`:
		var options string
		for _, option := range i.Options {
			options += `<label><input type="radio" name="` + namePrefix + i.Name + `" value="` + option.Value + `"`
			if option.Checked || option.Value == value {
				options += ` checked`
			}
			options += `>` + option.Text + `</label>`
		}
		return options
	default:
		return `<input class="form-control" type="` + i.Type + `" name="` + namePrefix + i.Name + `" value="` + value + `"` + i.BuildHTMLAttrs() + ` />`
	}
}

func (i Input) RenderHTMLLabel() string {
	return `<label class="col-sm-2 control-label">` + i.Label + `</label>`
}

type Inputs []Input

func (i Inputs) RenderCaddyfile() []string {
	results := make([]string, len(i))
	for i, input := range i {
		value := input.Value
		if len(value) == 0 && len(input.Default) > 0 {
			value = input.Default
		}
		results[i] = input.Name + ` ` + value
	}
	return results
}

type HTML struct {
	Label string
	Input string
	Help  string
}

func (i Inputs) RenderHTMLs(namePrefix string) []HTML {
	results := make([]HTML, len(i))
	for i, input := range i {
		results[i] = HTML{
			Label: input.RenderHTMLLabel(),
			Input: input.RenderHTMLInput(namePrefix),
			Help:  input.RenderHTMLHelp(),
		}
	}
	return results
}

func (i Inputs) Clone() Inputs {
	results := make(Inputs, len(i))
	copy(results, i)
	return results
}

type Provider struct {
	Provider string
	Title    string
	Inputs   Inputs
}

var inputsRegistry = map[string]Provider{}

func GetInputs(provider string) Inputs {
	return inputsRegistry[provider].Inputs
}

func GetProviders() []string {
	providers := make([]string, 0, len(inputsRegistry))
	for provider := range inputsRegistry {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

func RegisterInputs(provider string, title string, inputs Inputs) {
	inputsRegistry[provider] = Provider{Provider: provider, Title: title, Inputs: inputs}
}

func Get(provider string) Provider {
	return inputsRegistry[provider]
}
