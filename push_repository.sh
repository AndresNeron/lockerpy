#!/bin/bash

# Before executing this script, execute this:
# eval "$(ssh-agent -s)"; ssh-add ~/.ssh/counter_ed25519; git config --global user.name "AndresNeron"; git config --global user.email "andres.finanzas0820@gmail.com"

# That way is avoided the introduction of the passphrase each time.

# Execute the script like this in the root project.
# ./push_repository.sh


Project_path="$(dirname "$(realpath $0)")"
GitHub_repo="/home/ainode/GitHub/lockerpy"

# Move to the GitHub repository
cd "$Github_repo" || return 1



copy_files(){
        echo "[!] Copying files to $GitHub_repo"

        # Update the code written in the Project github repository
		rsync -avz "$Project_path/locker.py" "$GitHub_repo"
		rsync -avz "$Project_path/RSA/encryption_rsa.py" "$GitHub_repo/RSA"
		#rsync -avz "$Project_path/RSA/lock_pem.pub" "$GitHub_repo/RSA"
		#rsync -avz "$Project_path/installer.sh" "$GitHub_repo"
		#rsync -avz "$Project_path/installer2.sh" "$GitHub_repo"
		rsync -avz "$Project_path/requirements.txt" "$GitHub_repo"
		rsync -avz "$Project_path/README.md" "$GitHub_repo"

		echo
        tree "$GitHub_repo" -L 2
        printf "\n\n[!] Files already copied to %s\n\n" "$GitHub_repo"

}

backup_git(){
        echo

		cd "$Github_repo" || return 1

		git add .
		git commit -m "update"
		git push -u origin main

        echo
}

copy_files
backup_git
