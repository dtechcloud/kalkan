# Semgrep rules

This is the central Semgrep rule repository that hosts the Semgrep rules
for the [GitLab semgrep analyzer](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep).

The repository is structured as follows:

```
.
├── mappings
│   ├── find_sec_bugs.yml
│   ├── eslint.yml
│   └── ...
├── rules
│   ├── lpgl
│   │   ├── java
│   │   │   ├── webview
│   │   │   │   ├── rule-ignore_ssl_certificate_error.yml
│   │   │   │   ├── rule-ignore_ssl_certificate_error.java
│   │   │   │   └── ...
│   │   │   └── ...
│   │   ├── python
│   │   │   └── ...
│   │   └── ...
│   ├── lpgl-cc
│   │   ├── java
│   │   │   └── ...
│   │   └── ...
│   └── ...
├── c
│   ├── buffer
│   │   ├── rule-strcpy.yml
│   │   ├── test-strcpy.c
│   │   ├── rule-memcpy.yml
│   │   └── test-memcpy.c
│   └── ...
└── javascript
│   └── ...
└── ...
```

The structure above follows the pattern:

```
rules/<license>/<language>/<ruleclass>/rule-<rulename>\.(yml|<ext>)
```

where:

1. `<license>` is the license of all the rules underneath
1. `<language>` the target programming language
1. `<ruleclass>` a descriptive name for the class of rules underneath
1. `<rulename>` a descriptive name for the actual rule
1. `<ext>` the usual file extension for `<language>`

Older rules follow the `<language>/<ruleclass>/rule-...` pattern, and the
newer one above should be preferred whenever possible.

The `mappings` directory includes the rule-pack configuration.

## Makefile

The [Makefile](Makefile) defines a few targets that are helpful when working on rules:

```console
$ make help
TARGETS:
  test                  test all rules with Semgrep
  watch                 watch for file changes and auto-run affected tests
  help                  prints this message
```

## Formatting guidelines

Rules contained in this repository have to adhere to the following format:

- Use `"` for strings, otherwise the YAML literal block |
- No collapsing of array elements
- max line-length/text-width: 100 characters
- indentation: 2 spaces
- every rule has to have a corresponding test-case
- if provided, comments-section at the top of the rule file
- every YAML files starts with `---`

## Mappings

The mappings directory in this repository contains YAML configuration files
that map native analyzer ids (e.g. Bandit, Brakeman, etc) to the corresponding Semgrep rules.

The intention of mapping files is to, first and foremost, separate analyzer-specific information 
from the actual rules and, secondly, to provide a non-intrusive way of generating
rule-packs or rule-sets (across language or analyzer boundaries) for different purposes.

Mapping files are located under the `mappings/` directory where the filename refers 
to the rulepack and/or analyser that is represented by the set of rules used in the 
respective file. If you want the rules to be included in the GitLab standard ruleset 
and the rule does not fit into one of the rule-packs (or analysers) that are already 
available in the `mappings/` directory, you can add your mappings to the
`mappings/gitlab_<license>_<language>.yml` file where `<license>` is a suitable
license dictated by the source from which the rules is sourced and `<language>`
is a placeholder of the language to which the rule refers to. 

If you want to integrate a new rule that was developed from scratch, you can
add a corresponding mapping to `mappings/gitlab_ee_<language>.yml` file.
When determining what license should apply to a particular rule you are mapping, 
refer to this [internal guidance](https://internal.gitlab.com/handbook/product/sec/secure/sast/rule-licensing/). 

Mappings are also used to automatically assemble rule-packs. The snippet below 
illustrates an example with mapping files for the `bandit` analyzer. The `native_id`
section includes some information about the
native analyzer id, i.e., meta-information that the original analyser (in this case bandit) 
attaches to the finding it produces. The actual rule mappings are defined in the `mappings`
section. Each mapping maps a native analyser rule id (in the example below `B301`) to a set of semgrep files
in this repository that resemble, or are ideally de facto equivalent to, that particular native rule.

```yaml
bandit:
  native_id:
    type: "bandit_test_id"
    name: "Bandit Test ID: $ID"
    value: "$ID"
  mappings:
  - id: "B301"
    rules:
    - path: "python/deserialization/rule-pickle"
      primary_id: "bandit.B301-1"
      id: "bandit.B301-1"
    - path: "python/deserialization/rule-cpickle"
      primary_id: "bandit.B301-2"
      id: "bandit.B301-2"
    - path: "python/deserialization/rule-dill"
      primary_id: "bandit.B301-3"
      id: "bandit.B301-3"
    - path: "python/deserialization/rule-shelve"
      primary_id: "bandit.B301-4"
      id: "bandit.B301-4"
  # ...
```

The anatomy of a mapping file is explained in more detail below.

1. *id* is used to generate stable and unique semgrep rule identifiers in the semgrep rule-pack that corresponds to a mapping file.
1. *primary_id* helps to generate stable vulnerability primary identifiers that are attached to vulnerabilities as they are generated by the [GitLab Semgrep analyzer](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep) (in the `gl-sast-report.json`) for deduplication purposes.  
1. *native_id* is the entry that exactly resembles the structure of the vulnerability identifier as it would be generated by the native analyzer. This is going to be added to the `gl-sast-report.json` produced by the [GitLab Semgrep analyzer](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep) and made available in the Vulnerabiliy Report.
1. *mappings* includes the native analyzer id (in the case above `B301` which refers to [one of the rules of the python analyzer bandit](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b301-pickle)). The `rules` array points to files in the repository to which this rule refers to. In other words, the logic off `B301` is implemented in the four files listed in the snippet above.

We use two different types of identifiers `id` and `primary_id` to support rule splitting: multiple semgrep rules (`id`) can be mapped to a single native analyser’s rule (`primary_id` ). 

## Data sources

The rules and test-cases in this repository are partially sourced from the
sources listed below:
1. https://github.com/returntocorp/semgrep-rules
1. https://github.com/PyCQA/bandit
1. https://github.com/nodesecurity/eslint-plugin-security
1. https://github.com/jsx-eslint/eslint-plugin-react
1. https://github.com/david-a-wheeler/flawfinder/blob/master/flawfinder.py

The details are listed in the headers of all the rule end test-files including
the licensing information and proper attribution.

## Contributing

If you know about a pattern that isn't present in this repo or refinements that
could be applied to the rules in this repository, you can contribute by opening
an issue, or even submit an improvement to the rule files/test cases in this
repository.

## Versioning

We apply the following semantic versioning scheme to this repository:

1. patch version increment: for updated/patched/added rules.
1. minor version increment: backwards-compatible YAML schema changes (e.g., adding/removing optional fields).
1. major version increment: non-backwards-compatible YAML schema changes (e.g., adding/removing required fields)

## SAST Rules release process

New SAST rule releases must be incorporated into the [semgrep analyzer](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)
to take effect. To request a new semgrep release, create a release issue using the instructions in the 
[SAST release issue template](https://gitlab.com/gitlab-org/gitlab/-/issues/new?description_template=SAST%20Rules%20release).

## Credits

We would like to thank the following authors very much for their valuable
contributions.

| Author            | MRs/Issues |
| ----------------- | ---------- |
| @masakura         | !99, !107  |
| @niklas.volcz     | !183       |
| @pieter39         | !668       |
