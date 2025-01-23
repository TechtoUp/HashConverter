import json
import base64

# Function to convert hex to ASCII
def hex_to_ascii(hex_string):
    try:
        # Convert hex to bytes and decode into ASCII format
        bytes_obj = bytes.fromhex(hex_string)
        ascii_str = bytes_obj.decode('utf-8', errors='replace')  # 'replace' replaces un-decodable characters
        return ascii_str
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

# Function to convert hex to unknown string (complex encoding pattern)
def hex_to_unknown(hex_string):
    unknown_string = ""
    block_size = 32  # 32 characters of hex string to encode at once
    # Process the hex string in blocks of 32 characters
    for i in range(0, len(hex_string), block_size):
        hex_block = hex_string[i:i + block_size]
        if len(hex_block) < block_size:
            # Handle incomplete blocks
            hex_block = hex_block.ljust(block_size, '0')
        
        # Convert this block to base64 (intermediate step for encoding)
        base64_block = base64.b64encode(bytes.fromhex(hex_block)).decode('utf-8')
        unknown_string += base64_block

    return unknown_string

# Function to convert unknown string back to hex
def unknown_to_hex(unknown_string):
    hex_string = ""
    # Decode the unknown string from base64 back to hex
    for i in range(0, len(unknown_string), 44):  # Base64 encoding typically results in 44 chars per block
        base64_block = unknown_string[i:i + 44]
        decoded_bytes = base64.b64decode(base64_block)
        hex_block = decoded_bytes.hex()
        hex_string += hex_block

    return hex_string

# Function to process the dataset and convert between formats
def process_single_entry(data):
    # Ensure the input has the required structure
    if 'original' not in data or not isinstance(data['original'], dict):
        print("Invalid data structure")
        return

    original_data = data['original']
    
    # Get the hex and unknown values
    hex_data = original_data.get('hex', '')
    unknown_data = original_data.get('unknown', '')

    # Step 1: Convert hex to ASCII
    print("\n--- Hex to ASCII ---")
    ascii_data = hex_to_ascii(hex_data)
    print(f"ASCII Data:\n{ascii_data}")

    # Step 2: Convert hex to Unknown
    print("\n--- Hex to Unknown ---")
    unknown_from_hex = hex_to_unknown(hex_data)
    print(f"Unknown Data:\n{unknown_from_hex}")

    # Step 3: Convert Unknown back to Hex (for verification)
    print("\n--- Unknown to Hex ---")
    hex_from_unknown = unknown_to_hex(unknown_data)
    print(f"Hex Data:\n{hex_from_unknown}")

# Function to process a JSON file
def process_json_file(file_path):
    try:
        # Open and read the JSON file
        with open(file_path, 'r') as file:
            data = json.load(file)

        # Process each entry in the JSON file
        for entry in data:
            print(f"\nProcessing entry:")
            process_single_entry(entry)

    except json.JSONDecodeError:
        print("Error reading the JSON file. Ensure it's properly formatted.")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")

# Main function to run the tool
def main():
    while True:
        print("\n=====================================")
        print("Hex-ASCII Converter Tool")
        print("=====================================")
        print("Select an operation:")
        print("[1] Process single data entry")
        print("[2] Process JSON file")
        print("[3] Exit")

        # Get user choice
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            # For single entry, user enters JSON data manually
            json_input = input("Enter the JSON data as a string: ")
            try:
                data = json.loads(json_input)
                process_single_entry(data)
            except json.JSONDecodeError:
                print("Invalid JSON format provided.")
        elif choice == '2':
            # For file processing, ask for file path
            file_path = input("Enter the path to the input JSON file: ")
            process_json_file(file_path)
        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select between 1 and 3.")

if __name__ == "__main__":
    main()