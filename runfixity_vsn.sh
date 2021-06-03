#!/bin/bash

DKROOT="/dkarcs"
cksum_algo="md5sum"
eq_library=50
sam="false"
dir="null"
file="null"
copy=0

# This script has no field checks. Meant to be called from "runfixity.sh".
# runfixity_vsn.sh $logdir $vsn $copy $nfiles $narcs $size $vsn_instructions

# Process arguments ; Provide usage instructions
#

logdir=$1
vsn=$2
copy=$3
nfiles=$4
narcs=$5
size=$6
vsn_instructions=$7

# Assumptions:
aa_all="${logdir}/all_archive_audit.txt"
all_inos_md5="${logdir}/all_inos_md5.txt"

#echo
#echo "vsn-instructions file: $vsn_instructions"
#echo "vsn: $vsn"
#echo "logdir: $logdir"
#echo "copy: $copy"
#echo
#exit 0

# ---------------------- # 
# ---------------------- # 
# ---------------------- # 

# https://www.linuxjournal.com/content/use-date-command-measure-elapsed-time
# If called with no arguments a new timer is returned.
# If called with arguments the first is used as a timer
# value and the elapsed time is returned in the form HH:MM:SS.
#printf "Elapsed time: %s\n" $(timer $tmr)
#
function timer()
{
    if [[ $# -eq 0 ]]; then
        echo $(date '+%s')
    else
        local  stime=$1
        etime=$(date '+%s')

        if [[ -z "$stime" ]]; then stime=$etime; fi

        dt=$((etime - stime))
        ds=$((dt % 60))
        dm=$(((dt / 60) % 60))
        dh=$((dt / 3600))
        printf '%d:%02d:%02d' $dh $dm $ds
    fi
}

tmr=$(timer)

# --------------------------------#
# ------ SET UP LOGGING --------- #
# --------------------------------#

# Create log 
log="${logdir}/${vsn}_RUNFIXITY.LOG"
touch $log

function logmsg()
{
    printf "%s: $1\n" $(timer $tmr) | tee -a $log
}

# --------------------------------#
# ---- END SET UP LOGGING ------- #
# --------------------------------#

# ------------------------------------------------------------ #
# Now generate checksums for given copy-no and VSN (if applicable).
# ------------------------------------------------------------ #

# Create output files.
vsn_symlinks="${logdir}/${vsn}_links.txt"
vsn_emptyfiles="${logdir}/${vsn}_emptyfiles.txt"
vsn_data="${logdir}/${vsn}_data.txt"
calc_data="${logdir}/${vsn}_calc.txt"
vsn_missing_checksums="${logdir}/${vsn}_missing_checksums.txt"
vsn_missing_files="${logdir}/${vsn}_missing_files.txt"
vsn_renamed_files="${logdir}/${vsn}_renamed_files.txt"
vsn_bad_checksums="${logdir}/${vsn}_bad_checksums.txt"
touch $vsn_symlinks
touch $vsn_emptyfiles
touch $vsn_missing_checksums
touch $vsn_missing_files
touch $vsn_renamed_files
touch $vsn_bad_checksums

echo "master.type master.offset master.md5 calc.md5 master.filename calc.filename" > $vsn_data
echo "type|offset|size|md5|filename" > $calc_data

# #> cat DKARC03-positions.txt 
# 17 20b d2/f11
# 2 20c d2/f12
#
# #> cat A00039-positions.txt 
#105 17ef7d 1568637
#103 1817b1 1578929

# tape is either 0 (disk) or 1 (yes, tape)
tape=0

# archive file (request for tape and dkarc for disk)
archive="null"

cat $vsn_instructions | while read count pos dkpath
do
  # For each position (copy 2 or 3) create request
  if [ $copy -ne 1 ]
  then
    # MASTER
    if [ $copy -eq 2 ]
    then
        # type, offset (decimal), size, md5, filename
        master=$(egrep "\|li.${vsn}\|${pos}\|" $all_inos_md5 | awk -F '|' '{printf "%d|%d|%d|%s|%s\n",$1,strtonum("0x"$5),$9,$2,$10}')
    elif [ $copy -eq 3 ]
    then
        master=$(egrep "\|li.${vsn}\|${pos}\|" $all_inos_md5 | awk -F '|' '{printf "%d|%d|%d|%s|%s\n",$1,strtonum("0x"$8),$9,$2,$10}')
    fi

    # CALC
    tape=1
    archive="${logdir}/REQUEST_${vsn}_${pos}"
    request -m li -v $vsn -p 0x${pos} $archive

  # For each dkpath (copy 1), build full dkpath
  else 
    # MASTER
    # type, offset (decimal), size, md5, filename
    master=$(egrep "\|${vsn}\/${dkpath}\|" $all_inos_md5 | awk -F '|' '{printf "%d|%d|%d|%s|%s\n",$1,$5,$6,$2,$7}')

    # CALC
    # type (0=file,1=dir,2=link), offset, md5, filename
    # output: type, offset, size, md5, filename
    tape=0
    archive="${DKROOT}/${vsn}/${dkpath}"
  fi

  # md5 - 32
  # sha1 - 40
  # sha256 - 64
  # sha512 - 128
  cksum=$(echo "$master"|head -1|cut -d '|' -f4)
  cksum_length=${#cksum}
  if [ $cksum_length -eq "32" ]
  then algo="MD5"
  elif [ $cksum_length -eq "40" ]
  then algo="SHA1"
  elif [ $cksum_length -eq "64" ]
  then algo="SHA256"
  elif [ $cksum_length -eq "128" ]
  then algo="SHA512"
  fi

  tapestring="TAPE"
  if [ $tape -eq "0" ]
  then
      tapestring="DISK"
  fi

  # SOFT LINKS
  egrep "\|${vsn}\/${dkpath}\|" $all_inos_md5 | egrep '^2' >> $vsn_symlinks

  # ZERO LENGTH (EMPTY) FILES (which often show up as bad checksums)
  if [ $tape -eq "0" ]
  then
      egrep "\|${vsn}\/${dkpath}\|" $all_inos_md5 | awk -F '|' '$6==0' >> $vsn_emptyfiles
  else 
      egrep "\|li.${vsn}\|${pos}\|" $all_inos_md5 | awk -F '|' '$9==0' >> $vsn_emptyfiles
  fi

  # CALC
  # type (0=file,1=dir,2=link), offset, md5, filename
  # output: type, offset, size, md5, filename
  echo "------------${archive} ${algo}-----------------" >> $calc_data
  calc=$(print_offset_cksum_from_tar $archive $algo $tapestring 2>/dev/null)
  echo "$calc" >> $calc_data

  if [ $tape -eq "1" ]
  then
      # remove the request (archive) file
      rm -f $archive
  fi

  # CREATE LOOKUP TABLE OF SORTS, combining inode data and calculated data from disk-archive copy
  # join output:
  # 1             2              3        4          5              6
  # master.type master.offset master.md5 calc.md5 master.filename calc.filename
  compare=$(join -t '|' --nocheck-order -1 2 -2 2 -o 1.1 1.2 1.4 2.4 1.5 2.5 -a 1 -e NULL <(echo "$master"|sort -t '|' -k2,2) <(echo "$calc"|sort -t '|' -k2,2))
  # Save this "lookup table" for possible future reference.
  echo "$compare" | egrep -v "NULL\|NULL\|NULL\|NULL\|NULL" >> $vsn_data

  # MISSING CHECKSUMS
  # NO_CKSUM_IN_INODE
  missing_checksums=$(echo "$compare" | egrep '^0' | grep 'NO_CKSUM_IN_INODE' | cut -d '|' -f5)
  if [ ${#missing_checksums} -gt 0 ]
  then
    echo "------------$archive---------------" >> $vsn_missing_checksums
    echo "$missing_checksums" >> $vsn_missing_checksums
  fi


  # MISSING FILES
  missing_files=$(echo "$compare" | egrep "\|NULL$" | cut -d '|' -f5)
  if [ ${#missing_files} -gt 0 ]
  then
    echo "------------$archive---------------" >> $vsn_missing_files
    echo "$missing_files" >> $vsn_missing_files
  fi

  # BAD CHECKSUMS
  compare_cksums=$(echo "$compare"|egrep '^0'|grep -v 'NO_CKSUM_IN_INODE')
  if [ $(echo "$compare_cksums"|egrep '^0'|wc -l) -gt 0 ]
  then
      # master.offset
      cksum_diff=$(diff -y --suppress-common-lines --suppress-blank-empty <(echo "$compare_cksums"|cut -d '|' -f2,3) <(echo "$compare_cksums"|cut -d '|' -f2,4) | cut -d '|' -f1)
      # filename, stored-md5, calc-md5
      bad_checksums=$(join -t '|' --nocheck-order -1 1 -2 2 -o 2.5 2.3 2.4 <(echo "$cksum_diff"|sort -k1,1) <(echo "$compare_cksums"|sort -t '|' -k2,2)|grep -v NULL|egrep -v '^\|')
      if [ ${#bad_checksums} -gt 0 ]
      then
        echo "------------$archive---------------" >> $vsn_bad_checksums
        echo "$bad_checksums" >> $vsn_bad_checksums
      fi
  fi

  # RENAMED FILES (does not count renamed symbolic links!)
  # master.offset
  fname_diff=$(diff -y --suppress-common-lines --suppress-blank-empty <(echo "$compare"|egrep '^0'|cut -d '|' -f2,5) <(echo "$compare"|cut -d '|' -f2,6)|cut -d '|' -f1)
  renamed_files=$(join -t '|' --nocheck-order -1 1 -2 2 -o 2.5 2.6 <(echo "$fname_diff"|sort -k1,1) <(echo "$compare"|egrep '^0'|sort -t '|' -k2,2) | grep -v NULL | awk -F '|' '{printf "%s -> %s\n", $1,$2}')
  if [ ${#renamed_files} -gt 4 ]
  then
    echo "------------$archive---------------" >> $vsn_renamed_files
    echo "$renamed_files" >> $vsn_renamed_files
  fi
done

#
# Finished reading this VSN. Compare checksums for files from this VSN.
#
#
n_missing_cksums=$(egrep -v '\-\-\-\-' $vsn_missing_checksums|wc -l|awk '{print $1}')
n_missing=$(egrep -v '\-\-\-\-' $vsn_missing_files|wc -l|awk '{print $1}')
n_renamed=$(egrep -v '\-\-\-\-' $vsn_renamed_files|wc -l|awk '{print $1}')
n_bad=$(egrep -v '\-\-\-\-' $vsn_bad_checksums|wc -l|awk '{print $1}')
n_links=$(egrep -v '\-\-\-\-' $vsn_symlinks|wc -l|awk '{print $1}')
n_empty=$(egrep -v '\-\-\-\-' $vsn_emptyfiles|wc -l|awk '{print $1}')

logmsg "Report for $vsn: $nfiles files ($size GB) in $narcs archives. Missing-Checksums: $n_missing_cksums; Missing: $n_missing; Renamed: $n_renamed; Bad Checksums: $n_bad; Symlinks: $n_links; Empty files: $n_empty"
