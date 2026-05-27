import os
import json
import re

def refine_from_folders(root_dir, output_file, max_emails=1000):
    """
    Scans the Enron raw data folders, extracts the email body, 
    and saves a human-readable (multi-line) JSON file.
    """
    refined_data = []
    
    print(f"🚀 Starting refinement in: {root_dir}")
    
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if len(refined_data) >= max_emails:
                break
                
            if file.endswith('.tar.gz'):
                continue
                
            try:
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
                    
                    parts = content.split('\n\n', 1)
                    if len(parts) > 1:
                        body = parts[1].strip()
                        body = re.sub(r'\s+', ' ', body)
                        
                        if 100 < len(body) < 1500:
                            refined_data.append(body)
            except Exception:
                continue
                
        if len(refined_data) >= max_emails:
            break

    # --- THE UPDATE IS HERE ---
    # indent=4 creates the multi-line structure you requested
    with open(output_file, 'w') as f:
        json.dump(refined_data, f, indent=4)
    
    print(f"✅ Success! Created {output_file} with {len(refined_data)} samples.")

if __name__ == "__main__":
    # Finds the directory where this script is located
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    # Matches the folder name 'raw data' from your screenshot
    input_folder = os.path.join(base_path, 'raw data')
    
    # Creates 'data/enron/' if it doesn't exist
    output_dir = os.path.join(base_path, 'data', 'enron')
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, 'refined_enron.json')

    if os.path.exists(input_folder):
        refine_from_folders(input_folder, output_path, max_emails=1000)
    else:
        print(f"❌ Error: Cannot find the folder: {input_folder}")
        print(f"📂 Current folder contains: {os.listdir(base_path)}")