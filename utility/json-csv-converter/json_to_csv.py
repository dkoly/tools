#!/usr/bin/env python3

import argparse
import json
import csv
import sys
from pathlib import Path
from typing import List, Dict, Any, Union

class JSONToCSVConverter:
    def __init__(self):
        self.delimiter = ','
        self.quotechar = '"'
        self.encoding = 'utf-8'
    
    def load_json(self, file_path: str) -> Union[List[Dict], Dict]:
        #Load JSON data from file
        try:
            with open(file_path, 'r', encoding=self.encoding) as f:
                data = json.load(f)
            return data
        except FileNotFoundError:
            raise FileNotFoundError(f"JSON file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        except Exception as e:
            raise Exception(f"Error loading JSON file: {e}")
    
    def load_json_from_stdin(self) -> Union[List[Dict], Dict]:
        #Load JSON data from standard input
        try:
            data = json.load(sys.stdin)
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format from stdin: {e}")
    
    def flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        # Flatten disct
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                # Handle arrays
                if v and isinstance(v[0], dict):
                    # Array of objects - create separate columns
                    for i, item in enumerate(v):
                        if isinstance(item, dict):
                            items.extend(self.flatten_dict(item, f"{new_key}[{i}]", sep).items())
                        else:
                            items.append((f"{new_key}[{i}]", item))
                else:
                    # Array of primitives - join as string
                    items.append((new_key, ', '.join(map(str, v)) if v else ''))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def normalize_data(self, data: Union[List[Dict], Dict], flatten: bool = False) -> List[Dict]:
        #Normalize JSON data for CSV conversion
        if isinstance(data, dict):
            # Single object - convert to list
            data = [data]
        elif not isinstance(data, list):
            raise ValueError("JSON data must be an object or array of objects")
        
        # Ensure all items are dictionaries
        normalized = []
        for item in data:
            if isinstance(item, dict):
                if flatten:
                    normalized.append(self.flatten_dict(item))
                else:
                    normalized.append(item)
            else:
                # Convert primitive values to dict
                normalized.append({'value': item})
        
        return normalized
    
    def get_all_keys(self, data: List[Dict]) -> List[str]:
        #Get all unique keys from list of dictionaries
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        return sorted(all_keys)
    
    def convert_to_csv(self, json_data: Union[List[Dict], Dict], output_file: str = None, 
                      flatten: bool = False, include_headers: bool = True,
                      selected_fields: List[str] = None, delimiter: str = ',',
                      encoding: str = 'utf-8') -> None:
        #Convert JSON data to CSV format
        
        # Normalize the data
        normalized_data = self.normalize_data(json_data, flatten)
        
        if not normalized_data:
            print("No data to convert")
            return
        
        # Get all possible keys
        all_keys = self.get_all_keys(normalized_data)
        
        # Filter keys if specific fields are selected
        if selected_fields:
            # Validate selected fields exist
            missing_fields = set(selected_fields) - set(all_keys)
            if missing_fields:
                print(f"Warning: Fields not found in data: {', '.join(missing_fields)}")
            fieldnames = [field for field in selected_fields if field in all_keys]
        else:
            fieldnames = all_keys
        
        if not fieldnames:
            print("No valid fields to export")
            return
        
        # Determine output destination
        output_file_obj = open(output_file, 'w', newline='', encoding=encoding) if output_file else sys.stdout
        
        try:
            writer = csv.DictWriter(output_file_obj, fieldnames=fieldnames, 
                                  delimiter=delimiter, quotechar=self.quotechar,
                                  quoting=csv.QUOTE_MINIMAL)
            
            if include_headers:
                writer.writeheader()
            
            for item in normalized_data:
                # Fill missing keys with empty strings
                row = {key: item.get(key, '') for key in fieldnames}
                # Convert non-string values to strings
                for key, value in row.items():
                    if value is None:
                        row[key] = ''
                    elif not isinstance(value, str):
                        row[key] = str(value)
                writer.writerow(row)
            
            if output_file:
                print(f"Successfully converted JSON to CSV: {output_file}")
                print(f"Rows: {len(normalized_data)}, Columns: {len(fieldnames)}")
        
        finally:
            if output_file and output_file_obj != sys.stdout:
                output_file_obj.close()
    
    def analyze_json_structure(self, json_data: Union[List[Dict], Dict]) -> Dict:
        #Analyze JSON structure and provide summary
        normalized_data = self.normalize_data(json_data)
        all_keys = self.get_all_keys(normalized_data)
        
        analysis = {
            'total_records': len(normalized_data),
            'total_fields': len(all_keys),
            'fields': {},
            'sample_record': normalized_data[0] if normalized_data else None
        }
        
        # Analyze each field
        for key in all_keys:
            field_info = {
                'present_in_records': 0,
                'data_types': set(),
                'sample_values': [],
                'null_count': 0
            }
            
            for record in normalized_data[:100]:  # Sample first 100 records
                if key in record:
                    field_info['present_in_records'] += 1
                    value = record[key]
                    
                    if value is None or value == '':
                        field_info['null_count'] += 1
                    else:
                        field_info['data_types'].add(type(value).__name__)
                        if len(field_info['sample_values']) < 3:
                            field_info['sample_values'].append(str(value)[:50])
            
            field_info['data_types'] = list(field_info['data_types'])
            analysis['fields'][key] = field_info
        
        return analysis
    
    def print_analysis(self, analysis: Dict) -> None:
        #Print JSON structure analysis
        print(f"\nJSON Structure Analysis:")
        print(f"  Total Records: {analysis['total_records']}")
        print(f"  Total Fields: {analysis['total_fields']}")
        print(f"\nField Details:")
        
        for field, info in analysis['fields'].items():
            coverage = (info['present_in_records'] / analysis['total_records']) * 100
            print(f"  {field}:")
            print(f"    Coverage: {coverage:.1f}% ({info['present_in_records']}/{analysis['total_records']})")
            print(f"    Data Types: {', '.join(info['data_types']) if info['data_types'] else 'No data'}")
            print(f"    Null/Empty: {info['null_count']}")
            if info['sample_values']:
                print(f"    Sample Values: {', '.join(info['sample_values'])}")
            print()
    
    def convert_multiple_files(self, input_files: List[str], output_dir: str = None,
                             **convert_options) -> None:
        #Convert multiple JSON files to CSV
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        for input_file in input_files:
            try:
                json_data = self.load_json(input_file)
                
                # Generate output filename
                input_path = Path(input_file)
                if output_dir:
                    output_file = Path(output_dir) / f"{input_path.stem}.csv"
                else:
                    output_file = input_path.parent / f"{input_path.stem}.csv"
                
                self.convert_to_csv(json_data, str(output_file), **convert_options)
                
            except Exception as e:
                print(f"Error processing {input_file}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert JSON to CSV format")
    parser.add_argument('input', nargs='?', help='Input JSON file (use - for stdin)')
    parser.add_argument('-o', '--output', help='Output CSV file (default: stdout)')
    parser.add_argument('-f', '--fields', nargs='+', help='Select specific fields to include')
    parser.add_argument('--flatten', action='store_true', help='Flatten nested objects')
    parser.add_argument('--no-headers', action='store_true', help='Skip CSV headers')
    parser.add_argument('-d', '--delimiter', default=',', help='CSV delimiter (default: comma)')
    parser.add_argument('-e', '--encoding', default='utf-8', help='File encoding (default: utf-8)')
    parser.add_argument('--analyze', action='store_true', help='Analyze JSON structure without converting')
    parser.add_argument('--batch', nargs='+', help='Convert multiple JSON files')
    parser.add_argument('--output-dir', help='Output directory for batch conversion')
    
    args = parser.parse_args()
    
    if not args.input and not args.batch:
        parser.print_help()
        return
    
    converter = JSONToCSVConverter()
    
    try:
        if args.batch:
            # Batch conversion
            convert_options = {
                'flatten': args.flatten,
                'include_headers': not args.no_headers,
                'selected_fields': args.fields,
                'delimiter': args.delimiter,
                'encoding': args.encoding
            }
            converter.convert_multiple_files(args.batch, args.output_dir, **convert_options)
        
        else:
            # Single file conversion
            if args.input == '-':
                json_data = converter.load_json_from_stdin()
            else:
                json_data = converter.load_json(args.input)
            
            if args.analyze:
                analysis = converter.analyze_json_structure(json_data)
                converter.print_analysis(analysis)
            else:
                converter.convert_to_csv(
                    json_data,
                    args.output,
                    flatten=args.flatten,
                    include_headers=not args.no_headers,
                    selected_fields=args.fields,
                    delimiter=args.delimiter,
                    encoding=args.encoding
                )
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()