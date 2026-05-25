#!/bin/bash
############################################################
# Student Name: Uri Wertheim
# Student Code: S6
# Class Code: TMagen773638
# Lecturer: Natalie Erez
# Project: Analyzer - NX212
############################################################
#
#
welcome() 
{
	# Define a separator for the terminal
    SEP="--------------------------------------------------------------"
    SEP1="- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - "
    echo
	echo "$SEP1"
    echo "       Welcome to THE ANALYZER v1.0        "
    echo "$SEP1"
    echo
}
#  - - - 1.1 ROOT CHECK 
#
#Function: check root: Check the current user; exit if not ‘root’.
#
check_root()
{
    if [[ $EUID -ne 0 ]]; 
		then
			echo "This script must be run as root. Exiting."
			exit 1
		else 
			echo "Hello Superuser"
			echo
    fi
}
# 1.2 USER INPUT & FILE CHECK
#
#function: get_target_file: Allow the user to specify the filename;
#make sure the file exists. not empty and not an archive.
#Prepairing folder for the artifacrs and documentation
#initialize the report document
get_target_file() 
{
	echo "$SEP"
	echo
    read -p "Enter the path to the evidence file (HDD/Memory image): " target
    
    # The -f flag checks if the file exists and is a regular file
    if [[ ! -f "$target" ]]; # if not:
		then
			echo "[-] Error: File '$target' not found!"
			echo "[-] Exiting..."
			exit 1
			
		else
			sleep 1
			echo "[+] File found and validated"
			echo "$SEP"
			#export makes the Variable a global one
			export TARGET_FILE=$target 
			
		# if the file is archive, advising the user to unzip it before analyzing
		if [[ "$TARGET_FILE" =~ \.(zip|rar|tar|7z|gz)$ ]]; then
			echo "$SEP"
			echo "[!] WARNING: You have selected a compressed (.zip) file."
			echo "[!] Note: Forensic tools (Binwalk/Foremost) often perform"
			echo "[!] better on the unzipped raw contents."
			echo "[!] We advise unzipping for the most thorough analysis."
			echo "$SEP"
			echo
			read -p "[!] Would you like to quit now (y/n)? " choice
			if [[ $choice == y ]]; then 
				echo "[+] Smart Choice! Exitting... "
				echo "[+] Please unzip the file and come back!"
				exit 1
			fi
		fi
    fi
    
    # - - -1.5 Data should be saved into a directory
    #Extract the name from the path and create the timestamp
    #basename clean the full path and leaves just the file name
		FILE_NAME=$(basename "$TARGET_FILE")
		TIMESTAMP=$(date +%Y%m%d_%H%M%S)
	#Combine them into one global variable. 
	#using $(pwd) to make sure it is in current working dir
		export OUTPUT_DIR="$(pwd)/${FILE_NAME}_analysis_${TIMESTAMP}"
	# Create the folder (-p ensures it doesn't error if the folder exists)
		mkdir -p "$OUTPUT_DIR"
		echo "[+] Analysis folder created at: $OUTPUT_DIR"
		echo "$SEP"
		cd "$OUTPUT_DIR"
	sleep 1
	
	# Initialize the Master Report in the Output Directory
		REPORT_FILE="${OUTPUT_DIR}/forensic_report.txt"
		REPORT_FILE="$(pwd)/forensic_report.txt"
		echo "==========================================" > "$REPORT_FILE"
		echo "ANALYZER FORENSIC REPORT - $(date)" >> "$REPORT_FILE"
		echo "Target File: $TARGET_FILE" >> "$REPORT_FILE"
}
# 1.3 TOOL INSTALLATION 
#
# --- function: install_tools : installs the forensics tools if missing
#
install_tools() {
	echo 
    echo "Running system check and installing required forensics tools..."
    echo "$SEP1"

    declare -A TOOLS=( 
        ["python3"]="python3"
        ["pip3"]="python3-pip"
        ["git"]="git"
        ["bulk_extractor"]="bulk-extractor" 
        ["foremost"]="foremost" 
        ["strings"]="binutils" 
    )

    echo "[*] Updating package lists..."
    sudo apt-get update --fix-missing -y

    for cmd in "${!TOOLS[@]}"; do
        package=${TOOLS[$cmd]}
        if ! command -v "$cmd" &>/dev/null; then
            echo "[!] $cmd missing. Installing $package..."
            sudo apt-get install -y --fix-missing "$package"
            echo "$SEP!" >> "$REPORT_FILE"
            echo "${cmd} was installed" >> "$REPORT_FILE"
            echo "$SEP!" >> "$REPORT_FILE"
        else
            echo "[+] $cmd is already installed."
        fi
    done

    # Optimized Volatility Check/Install
    if command -v vol &>/dev/null || command -v volatility &>/dev/null; then
        echo "[+] Volatility 3 is already installed and ready."
    else
        echo "[!] Volatility 3 not found. Installing via pip3..."
        sudo pip3 install git+https://github.com/volatilityfoundation/volatility3.git --break-system-packages

        # Create symbolic link if needed
        if [ -f "$HOME/.local/bin/vol" ]; then
            sudo ln -s "$HOME/.local/bin/vol" /usr/local/bin/vol 2>/dev/null
        fi

        # Final check only if we just tried to install it
        if ! command -v vol &>/dev/null && ! command -v volatility &>/dev/null; then
            echo "[!!!] Critical Error: Volatility 3 installation failed."
            exit 1
        fi
        echo "[+] Volatility 3 installation successful."
        echo "$SEP!" >> "$REPORT_FILE"
        echo "$Volatility 3 was installed" >> "$REPORT_FILE"
        echo "$SEP!" >> "$REPORT_FILE"
    fi
}
# - - - 1.7 Check for human-readable (exe files, passwords, usernames, etc.).
#
# # # CARVING AND ANALYZING WITH FEW DIFFERENT TOOLS
#
# STRINGS:
strings_analyze()
{    	
	#ensuring we are at the right directory
	if [[ $(pwd) != "$OUTPUT_DIR" ]]; then
		cd "$OUTPUT_DIR" 
	fi
	
    # creating subdir for strings artifacts
    mkdir -p "${FILE_NAME}_STRINGS"
    #echo "[*] Creating folder: ${FILE_NAME}_STRINGS"
    #echo "[*] Strings artifacts will be saved in this folder"   
     
    sleep 1
    
    # Moving into the new folder so artifacts save there directly
    cd "${FILE_NAME}_STRINGS"
    
    # carving the file into a temporary file to save time
    strings "$TARGET_FILE" > temp_strings.tmp 
    echo
	echo "$SEP"    
    echo "[*] Running Strings"
	echo "$SEP1"
    
	sleep 2
	
    # Define what we are looking for and where to save it
    # The user can add his own keywords for the search.
    echo "[!] The program will determine, by default, for passwords, mail addresses, user names and ip addresses."
    read -p "[!] if you would like to add keywords, please type y, otherwise, type n: " answer
    
    # self healing loop:
    until [[ "$answer" =~ ^[yn]$ ]] ; do
        read -p "[-] invalid Choice. maybe your caps lock is on or your keyboard language is not English. choose y or n then press Enter: " answer
    done
    
	# loop that accepts and extracts user keywords
    if [[ "$answer" == "y" ]]; then
		read -p "[*] Type as many keywords, as you like. Separated with space: " user_keys
		
		sleep 1
		
            for key in $user_keys ; do
                echo -e "extracting lines with -$key- to new file: $key.txt"
                grep -iE -n "$key" temp_strings.tmp > "${key}.txt"
                sleep 1
            done
            
    fi
    
    # default search
		echo "extracting default keywords: password,passwd,pwd,secret,user,admin,login,account,"
		echo "ip adresses and emails look alike" 
		echo "[>]" 
		grep -iE -n "password|passwd|pwd|secret" temp_strings.tmp > passwords.txt
		grep -iE -n  "user|admin|login|account" temp_strings.tmp > users.txt
		grep -oE -n "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" temp_strings.tmp > ips.txt
		grep -iE -n "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}" temp_strings.tmp > emails.txt
    
	sleep 1
	
    echo "$SEP1"
    # Cleaning up the temp file
		rm -f temp_strings.tmp
		
    # counting results and documenting. cleanup of empty results
		echo "[*] Cleaning up empty artifacts..."
		echo
		echo "==========================================" >> "$REPORT_FILE"
		echo "--- -Strings Analysis Results ------------" >> "$REPORT_FILE"
		echo "==========================================" >> "$REPORT_FILE"
    
    for result_file in *.txt; do
    
        if [ -s "$result_file" ]; then
        
            # Count lines and append to the report one level up
            LINE_COUNT=$(wc -l < "$result_file")
            echo "[+] $result_file: $LINE_COUNT lines found" >> "$REPORT_FILE"
            
        else
            echo "    [-] Removing empty file: $result_file"
            rm "$result_file"
        fi
        
    done
    
    sleep 1
    
    echo "[+] Strings analysis complete."
    echo "[+] Results saved in ${FILE_NAME}_STRINGS"
    echo "$SEP"   
}
#
# BULK_EXTRACTOR:
bulk_extractor_analyze()
{
	echo
	echo "$SEP"
    echo "[*] Starting bulk_extractor..."
    echo "$SEP"
        
    cd "$OUTPUT_DIR"
    
    # Run bulk_extractor
    bulk_extractor -o "${FILE_NAME}_BULK" "$TARGET_FILE" 2>&1 | tee >(head -n 5) > /dev/null
    sleep 2
    # Go inside to do the cleanup of 0-byte files
    cd "${FILE_NAME}_BULK"
    find . -type f -size 0 -delete
    
    # --- REPORTING PHASE ---
    
    # Header for the Report
    echo -e "\n==========================================" >> "$REPORT_FILE"
    echo "       BULK EXTRACTOR ANALYSIS" >> "$REPORT_FILE"
    echo "==========================================" >> "$REPORT_FILE"

    # 1. THE TREE (One level up)
    echo "--- Directory Structure (Visual Map) ---" >> "$REPORT_FILE"
    # We use '..' to show the folder we are currently in from the perspective of its parent
    tree -h -s -F -L 2 .. >> "$REPORT_FILE"
    
    echo -e "\n--- Feature Counts ---" >> "$REPORT_FILE"
    
    # 2. COUNT ALL REMAINING FILES
    for feat_file in *.txt; do
        [[ "$feat_file" == "forensic_report.txt" ]] && continue
        if [ -f "$feat_file" ]; then
            COUNT=$(cat "$feat_file" | wc -l)
            CLEAN_NAME=$(basename "$feat_file" .txt)
            echo "[+] $CLEAN_NAME: $COUNT entries found" >> "$REPORT_FILE"
        fi
    done
	sleep 1
	# - - - 1.6 Attempt to extract network traffic; if found, display to the user the location and size.
    #
    if [ -f "packets.pcap" ]; then
        packets=$(cat packets.pcap | wc -l)
        echo -e "\n--- Network Records ---" >> "$REPORT_FILE"
        echo "[!] Network traffic: ${packets} packets captured and saved in ${FILE_NAME}_BULK/packets.pcap" >> "$REPORT_FILE"
        echo "[!] Network traffic identified: ${packets} packets."
    fi
    #massage on screen:
    echo 
    echo "[+] Bulk Extraction complete. "
    echo "[+] Section added to report file ${REPORT_FILE}"
    sleep 1
}
# FOREMOST: File Carving Analysis
foremost_analyze()
{
    echo "$SEP"
    echo "[*] Starting Foremost File Carving..."
    echo "$SEP"

    OUT_DIR="${OUTPUT_DIR}/${FILE_NAME}_FOREMOST"
    
    # Run foremost
    sudo foremost -i "$TARGET_FILE" -o "$OUT_DIR" &> /dev/null

    # --- REPORTING PHASE ---
    {
        echo -e "\n=========================================="
        echo "           FOREMOST CARVING RESULTS"
        echo "=========================================="
        echo
        echo "RECOVERED FILE BREAKDOWN:"
        
        if [ -d "$OUT_DIR" ]; then
            find "$OUT_DIR" -maxdepth 1 -type d -not -path "$OUT_DIR" | while read -r dir; do
                ext=$(basename "$dir")
                count=$(find "$dir" -type f | wc -l)
                if [ "$count" -gt 0 ]; then
                    echo "  [>] ${ext^^}: $count files"
                fi
            done
        else
            echo "  [!] No files recovered."
        fi
        echo "$SEP1"
    } >> "$REPORT_FILE"
    #massage on screen:
	echo
    echo "[+] Foremost carving complete. Breakdown added to report."
}
#
# 2.0 VOLATILITY MEMORY ANALYSIS
#each plugin will produce a full report text document
#while the most interesting artifacts will be saved to the main report doc
#
analyze_memory() {
    VOL_DIR="${OUTPUT_DIR}/Volatility_Data"
    mkdir -p "$VOL_DIR"
	echo
    echo "$SEP"
    echo "[*] Running Volatility Memory Analysis"
    echo "$SEP"
    # --- Add the Header to the Report ---
    {
        echo "=============================================================="
        echo "          VOLATILITY MEMORY ANALYSIS RESULTS                  "
        echo "=============================================================="
        echo "IMAGE SOURCE           : $TARGET_FILE"
        echo "REPORT TIME            : $(date)"
        echo "VOLATILITY DATA FOLDER : $VOL_DIR"
        echo "$SEP1"
    } >> "$REPORT_FILE"

    # --- Running windows.info first ---
    echo "[*] Extracting System Information (Triage)..."
    vol -q -f "$TARGET_FILE" windows.info > "$VOL_DIR/windows.info.txt" 2> "$VOL_DIR/vol_errors.log"
    
    if grep -q "Unsatisfied requirement" "$VOL_DIR/vol_errors.log"; then
        echo "[!] WARNING: Volatility symbols missing for this image."
        echo -e "\n[VOLATILITY ERROR]: Missing symbols. Summary limited.\n" >> "$REPORT_FILE"
    else
        {
            echo -e "\n[+] Plugin: windows.info (System Triage Summary)"
            # Capture key details like Kernel Base, SystemTime, and Is64Bit
            grep -E "Variable|Value|Kernel|SystemTime|Is64Bit|MachineType" "$VOL_DIR/windows.info.txt"
            echo "[i] See windows.info.txt for full system details."
        } >> "$REPORT_FILE"
    fi

    # --- The Plugins Loop: running the most important plugins ---
    #(in the next version there will be an option for the user to choose from the plugins' list

    W_PLUGINS=("windows.pslist" "windows.netscan" "windows.cmdline" "windows.registry.hivelist")

    for plugin in "${W_PLUGINS[@]}"; do
        RAW_FILE="${VOL_DIR}/${plugin}.txt"
        
        # Save FULL output to dedicated folder
        vol -q -f "$TARGET_FILE" "$plugin" 2>/dev/null | tail -n +3 > "$RAW_FILE"

        # Append Summary to main report. 
        {
            echo -e "\n[+] Plugin: $plugin (Summary Highlights)"
            case $plugin in
                "windows.pslist")
                    head -n 1 "$RAW_FILE"
                    # Highlight "The Big 10" and suspicious names
                    grep -E "System|lsass.exe|explorer.exe|FTK Imager|iexplore.exe|services.exe|winlogon.exe|taskeng.exe|smss.exe" "$RAW_FILE"
                    grep -iE "powershell|cmd|nc.exe|bitsadmin|mushroom.exe" "$RAW_FILE" | sed 's/^/[ALERT] /'
                    ;;

                "windows.netscan")
                    head -n 1 "$RAW_FILE"
                    echo -e "\n    [!] ACTIVE CONNECTIONS (ESTABLISHED):"
                    grep "ESTABLISHED" "$RAW_FILE" || echo "    No active connections."
                    echo -e "\n    [!] OPEN BACKDOORS (LISTENING/NON-LOCAL):"
                    grep "LISTENING" "$RAW_FILE" | grep -v "127.0.0.1" || echo "    No public listening ports."
                    ;;

                "windows.cmdline")
                    head -n 1 "$RAW_FILE"
                    # Filter for processes with arguments and increase depth to catch browser/office activity
                    echo -e "\n    [!] ACTIVE COMMAND LINE ARGUMENTS (Top 30):"
                    grep -vE "\t-\s*$" "$RAW_FILE" | grep -v "PID" | head -n 30
                    
                    # Highlight suspicious paths, including AppData and Downloads where malware often hides
                    echo -e "\n    [!] SUSPICIOUS EXECUTION PATHS:"
                    grep -iE "Users|Temp|Imager|AppData|Downloads|nc.exe|powershell" "$RAW_FILE" | sed 's/^/[ALERT PATH] /'
                    ;;

                "windows.registry.hivelist")
                    head -n 1 "$RAW_FILE"
                    # Include Amcache.hve as it is vital for tracking execution history
                    echo -e "\n    [!] CORE SYSTEM & EVIDENCE HIVES:"
                    grep -E "SYSTEM|SOFTWARE|SAM|SECURITY|Amcache" "$RAW_FILE"

                    # Group User-specific activity hives
                    echo -e "\n    [!] USER ACTIVITY HIVES:"
                    grep -iE "Users|NTUSER\.DAT|UsrClass\.dat" "$RAW_FILE"
                    ;;

                *)
                    head -n 10 "$RAW_FILE"
                    ;;
            esac
            echo "[i] See $(basename "$RAW_FILE") for full results."
        } >> "$REPORT_FILE"
        
        echo "[+] $plugin complete."
    done
}
#
# ==========================================
# GENERATE EVIDENCE AUDIT (Final Summary)
# ==========================================
generate_evidence_audit() {
    # 1. PERMISSIONS & INTEGRITY
    sudo chown -R $USER:$USER "$OUTPUT_DIR"
    sudo chmod -R 755 "$OUTPUT_DIR"
    
    # Calculate Hash (Only show on screen while calculating)
    echo "[*] Calculating Source File MD5 Hash..."
    SOURCE_HASH=$(md5sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. HEADER (Display to BOTH)
    {
        echo -e "\n\n=========================================="
        echo "         FINAL FORENSIC INVENTORY"
        echo "=========================================="
    } | tee -a "$REPORT_FILE"

    # 3. STATISTICS (Display to BOTH)
    {
        echo "Analysis End Time: $(date)"
        echo "Source File: $TARGET_FILE"
        echo "Source MD5 Hash: $SOURCE_HASH"
        
        # Calculate stats
        TOTAL_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
        TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | awk '{print $1}')
        
        echo "Total Files Recovered: $TOTAL_FILES"
        echo "Total Evidence Size: $TOTAL_SIZE"
        echo "------------------------------------------"
    } | tee -a "$REPORT_FILE"

    # 4. ZIP INDEXING 
    mapfile -t ALL_ZIPS < <(find "$OUTPUT_DIR" -type f -name "*.zip")
    if [ ${#ALL_ZIPS[@]} -gt 0 ]; then
        # Inform the terminal
        echo "[+] Indexed ${#ALL_ZIPS[@]} archives in the final report."
        
        # Write to report only (usually too much text for the terminal)
        echo -e "\n--- Nested Archive Index ---" >> "$REPORT_FILE"
        for zfile in "${ALL_ZIPS[@]}"; do
            REL_PATH=${zfile#$OUTPUT_DIR/}
            echo "[?] Archive: $REL_PATH" >> "$REPORT_FILE"
            unzip -l "$zfile" | sed '1,3d; $d; $d' >> "$REPORT_FILE"
            echo "------------------------------------------" >> "$REPORT_FILE"
        done
    else
        echo "[i] No ZIP archives were discovered during analysis." | tee -a "$REPORT_FILE"
    fi

	# 5. FINAL PACKAGING (3.3 Requirement)
		echo "$SEP"
		echo "[*] Packaging evidence into a ZIP archive..."

		# Ensure permissions are correct before zipping (crucial for Foremost files)
		sudo chown -R $USER:$USER "$OUTPUT_DIR"

		# Setup paths
		PARENT_DIR=$(dirname "$OUTPUT_DIR")
		FOLDER_NAME=$(basename "$OUTPUT_DIR")
		SAFE_NAME="${TARGET_NAME:-$FILE_NAME}"
		ZIP_NAME="${SAFE_NAME}_Case_Package_$(date +%Y%m%d_%H%M%S).zip"

		# Perform the zip from the parent directory
		# This avoids the "infinite loop" and "path junk" issues
		if ! (cd "$PARENT_DIR" && zip -rq "$ZIP_NAME" "$FOLDER_NAME"); then
			echo "--------------------------------------------------------------"
			echo "[!] Error: Failed to create ZIP package."
		fi

	# FINAL SUCCESS MESSAGE
	# We use ${PARENT_DIR}/${ZIP_NAME} to show the REAL location of the file
	{
		echo "$SEP"
		echo "[+] SUCCESS: Investigation Complete."
		echo "[+] Final Report: $REPORT_FILE"
		echo "[+] Evidence Package: ${PARENT_DIR}/${ZIP_NAME}"
		echo "$SEP"
	} | tee -a "$REPORT_FILE"
}
#
main_execution_function(){
	welcome
	check_root
	sleep 1
	install_tools
	sleep 1
	get_target_file
	sleep 2
	strings_analyze
	sleep 1
	bulk_extractor_analyze
	sleep 1
	foremost_analyze
	sleep 1
	analyze_memory
	generate_evidence_audit
}
main_execution_function
