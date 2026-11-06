### Result schema

Write `{{RESULT_FILE}}` as one JSON object that matches this JSON Schema. `additionalProperties: false` means that a field not listed in the schema makes the whole result invalid.

```json
{{SCHEMA}}
```

### Example of a valid result

The example shows the shape only. Its content is invented and in English; write your own content, with prose in {{LANG_NAME}}.

```json
{{EXAMPLE}}
```

When the file is written, reply with exactly one line: `DONE {{TASK_ID}}`
