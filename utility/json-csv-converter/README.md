# JSON to CSV Converter

A Python script to convert JSON data to CSV format with advanced features for data transformation and analysis.

## Features

- Convert JSON files or stdin to CSV format
- Handle nested objects with flattening options
- Batch convert multiple JSON files
- Analyze JSON structure before conversion
- Select specific fields for conversion
- Customizable delimiters and encoding
- Support for arrays and complex data structures
- Comprehensive error handling

## Requirements

- Python 3.6+

## Usage

### Basic Conversion

```bash
# Convert JSON file to CSV
python3 json_to_csv.py input.json -o output.csv

# Convert from stdin
cat data.json | python3 json_to_csv.py - -o output.csv

# Output to stdout
python3 json_to_csv.py input.json
```

### Advanced Options

```bash
# Flatten nested objects
python3 json_to_csv.py input.json -o output.csv --flatten

# Select specific fields
python3 json_to_csv.py input.json -o output.csv -f name email age

# Custom delimiter
python3 json_to_csv.py input.json -o output.csv -d ";"

# Skip headers
python3 json_to_csv.py input.json -o output.csv --no-headers

# Different encoding
python3 json_to_csv.py input.json -o output.csv -e "latin-1"
```

### Analysis and Batch Processing

```bash
# Analyze JSON structure
python3 json_to_csv.py input.json --analyze

# Batch convert multiple files
python3 json_to_csv.py --batch file1.json file2.json file3.json --output-dir csv_files/
```

## Examples

### Simple JSON Array
Input (`users.json`):
```json
[
  {"name": "John", "age": 30, "city": "New York"},
  {"name": "Jane", "age": 25, "city": "London"},
  {"name": "Bob", "age": 35, "city": "Paris"}
]
```

Command:
```bash
python3 json_to_csv.py users.json -o users.csv
```

Output (`users.csv`):
```csv
age,city,name
30,New York,John
25,London,Jane
35,Paris,Bob
```

### Nested JSON with Flattening
Input (`complex.json`):
```json
[
  {
    "name": "John",
    "address": {
      "street": "123 Main St",
      "city": "New York",
      "country": "USA"
    },
    "phones": ["555-1234", "555-5678"]
  }
]
```

Command:
```bash
python3 json_to_csv.py complex.json -o complex.csv --flatten
```

Output (`complex.csv`):
```csv
address.city,address.country,address.street,name,phones
New York,USA,123 Main St,John,"555-1234, 555-5678"
```

### Field Selection
Command:
```bash
python3 json_to_csv.py users.json -o selected.csv -f name city
```

Output (`selected.csv`):
```csv
city,name
New York,John
London,Jane
Paris,Bob
```

### Structure Analysis
Command:
```bash
python3 json_to_csv.py users.json --analyze
```

Output:
```
JSON Structure Analysis:
  Total Records: 3
  Total Fields: 3

Field Details:
  age:
    Coverage: 100.0% (3/3)
    Data Types: int
    Null/Empty: 0
    Sample Values: 30, 25, 35

  city:
    Coverage: 100.0% (3/3)
    Data Types: str
    Null/Empty: 0
    Sample Values: New York, London, Paris

  name:
    Coverage: 100.0% (3/3)
    Data Types: str
    Null/Empty: 0
    Sample Values: John, Jane, Bob
```

## Supported JSON Formats

### Array of Objects (Most Common)
```json
[
  {"field1": "value1", "field2": "value2"},
  {"field1": "value3", "field2": "value4"}
]
```

### Single Object
```json
{"field1": "value1", "field2": "value2"}
```

### Nested Objects
```json
[
  {
    "user": {
      "name": "John",
      "details": {"age": 30, "city": "NYC"}
    }
  }
]
```

### Arrays in Objects
```json
[
  {
    "name": "John",
    "skills": ["Python", "JavaScript", "SQL"],
    "projects": [
      {"name": "Project A", "status": "complete"},
      {"name": "Project B", "status": "in progress"}
    ]
  }
]
```

## Flattening Behavior

When `--flatten` is used:

- **Nested objects**: `user.address.city`
- **Array of primitives**: Joined with commas
- **Array of objects**: Indexed like `projects[0].name`

## Batch Processing

Convert multiple JSON files at once:

```bash
# Convert all JSON files in current directory
python3 json_to_csv.py --batch *.json --output-dir csv_output/

# Convert specific files with options
python3 json_to_csv.py --batch data1.json data2.json --output-dir results/ --flatten
```

## Error Handling

The script handles various error conditions gracefully:

- **Invalid JSON**: Clear error messages for malformed JSON
- **Missing files**: File not found errors with helpful messages
- **Empty data**: Graceful handling of empty JSON arrays/objects
- **Mixed data types**: Automatic conversion to strings for CSV compatibility
- **Encoding issues**: Support for different character encodings

## Performance Notes

- **Large files**: Processes data in streaming fashion where possible
- **Memory usage**: Loads entire JSON into memory (limitation of JSON format)
- **Batch processing**: Efficient for multiple small-to-medium files
- **Analysis mode**: Samples first 100 records for performance

## Common Use Cases

### Data Analysis
- Convert API responses to CSV for Excel/Google Sheets
- Transform log files from JSON to tabular format
- Prepare data for data analysis tools

### Data Migration
- Export data from NoSQL databases
- Convert configuration files
- Transform data between different systems

### Reporting
- Convert structured logs to reports
- Create CSV files for business intelligence tools
- Generate data exports for stakeholders

## Tips

1. **Use `--analyze` first** to understand your data structure
2. **Select specific fields** with `-f` for cleaner output
3. **Flatten nested data** when you need all details in columns
4. **Use batch processing** for multiple similar files
5. **Check encoding** if you see strange characters in output
