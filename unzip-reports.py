import os
import gzip
import zipfile
import shutil
import glob

def extract_archives(folder):
    folder = os.path.abspath(folder)
    extracted_count = 0

    # Process all files recursively
    for root, _, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            lower_name = file.lower()

            try:
                if lower_name.endswith(".zip"):
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        zf.extractall(root)
                        print(f"Extracted ZIP: {file_path}")
                        extracted_count += 1

                elif lower_name.endswith(".gz") or lower_name.endswith(".tgz"):
                    output_file = os.path.splitext(file_path)[0]
                    with gzip.open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    print(f"Extracted GZ: {file_path} -> {output_file}")
                    extracted_count += 1

            except Exception as e:
                print(f"Error extracting {file_path}: {e}")

    print(f"\nExtraction complete. {extracted_count} archive(s) processed.")

if __name__ == "__main__":
    target_folder = "dmarc_reports"  # Change this to your report folder
    extract_archives(target_folder)

