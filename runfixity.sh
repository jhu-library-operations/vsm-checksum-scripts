#!/bin/bash

DEBUG=0
DKPATH="/dkarcs"
cksum_algo="md5sum"
eq_library=50
sam="false"
dir="null"
file="null"
copy=100
uservsn="undefined"
joblimit_dk=6
joblimit_li=3
declare rfix_pid_grep

# Process arguments ; Provide usage instructions
#
# runfixity -h|-p <path> -c <copyno> [-v vsn]
# path = full path name, e.g.: /sam2/aorcollection
# copyno = 1 or 2 or 3 (4 - not supported / we don't use it anyway)

while getopts ":hp:c:f:v:" opt; do
    case ${opt} in
      h )
        echo "Usage:"
        echo "     runfixity -h         Display this message."
        echo "     runfixity -p <path> -c <copyno> [-v vsn]"
        echo " "
        echo "     -p <path> : full VSM path or VSM subdirectory"
        echo "     -c <copyno> : VSM copy - 1, 2, or 3 (4 not used or supported yet)"
        echo "     -v <vsn> : Only applicable for copies 2|3. Instead of calculating fixity"
        echo "                on all relevant VSNs (default), only calculate fixity for files"
        echo "                on given VSN."
        exit 0
        ;;
      p )
        dir=$OPTARG
        if [ ! -d $dir ]
            then echo "Path $dir does not exist. Exiting."
            exit 1
        fi
        ;;
      c )
        copy=$OPTARG
        if [ $copy -lt 1 ] || [ $copy -gt 3 ]
            then echo "Copy \"$copy\" is out of range [1-3]. Exiting."
            exit 1
        fi
        ;;
      f )
	file=$OPTARG
	if [ ! -d $dir ]
	    then echo "Path must be specified before filename! Exiting."
	    exit 1
	fi
	if [ ! -f $dir/$file ]
	    then echo "File $dir/$file does not exist. Exiting."
	    exit 1
	fi
        ;;
      v )
        uservsn=$OPTARG
        if [[ $uservsn == PM* ]] || [[ $uservsn == A* ]] || [[ $uservsn == B* ]]
            then cnt=`samcmd v $eq_library | grep $uservsn | wc -l`
            if [ $cnt != 1 ]
                then echo "VSN $uservsn is not in library eq:${eq_library}. Exiting."
                exit 1
            fi
	elif [[ $uservsn == "DKARC"* ]]
	    then if [ ! -d ${DKPATH}/${uservsn} ]
	        then echo "VSN $uservsn is not a valid Disk Archive. Exiting."
		exit 1
	    fi
        else
            echo "Invalid vsn specified: $uservsn. Exiting."
            exit 1
        fi
        ;;
      : )
        echo "Invalid Option: -$OPTARG requires an argument" 1>&2
        exit 1
        ;;
      \? )
        echo "Invalid Option: -$OPTARG" 1>&2
        exit 1
        ;;

    esac
done
shift $((OPTIND -1))

if [ $copy -lt 1 ] || [ $copy -gt 3 ]
    then echo "Copy is required. Exiting."
    exit 1
fi

if [[ $dir = "/sam"* ]]
    then sam=$(echo "$dir" | cut -d "/" -f1,2)
    ndir=$(echo "$dir" | cut -d "/" -f3-)
    dir=$ndir
    cd $sam
fi
if [[ `pwd` != "/sam"* ]]
    then echo "Something's not right. We should be in a top-level VSM directory. Exiting."
    exit 1
else
    sam=`pwd|sed 's/^\///'`
fi
if [ ! -d "temp" ]
    then echo "Missing \"${sam}/temp\". This program uses \"temp\" as a workspace. Exiting."
    exit 1
fi

# END ARGUMENT COLLECTION / VALIDATION

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

# Create log directory
run=`echo $(date +"%Y%m%d%H%M%S")`
logdir="/${sam}/temp/${run}"
mkdir ${logdir}
log="${logdir}/RUNFIXITY.LOG"
touch $log
echo "Setting up LOG file: $log"
echo

function logmsg()
{
    printf "%s: $1\n" $(timer $tmr) | tee -a $log
}

logmsg "Directory: `pwd`/${dir}"
if [ $file != "null" ]
    then logmsg "File: $file"
fi
logmsg "Copy: ${copy}"
if [ $uservsn != "undefined" ]
    then logmsg "Only considering files on VSN: $uservsn."
fi
logmsg " "
# --------------------------------#
# ---- END SET UP LOGGING ------- #
# --------------------------------#

t_size=0
n_inodes=0
n_files=0
n_dirs=0
n_links=0
n_cfiles=0
target=$dir

# fsdata=$(samfsdump -T -f /dev/null hamletcollection/ 2>&1| egrep 'Files:|Directories:|Symbolic links:|Files w/checksums'); n_files=$(echo "$fsdata"|grep "Files:"| cut -d: -f2|awk '{print $1}'); echo "n_files = $n_files"

if [ $file != "null" ]
    then target="$dir/$file"
fi

if [ $uservsn != "undefined" ]
then
    # target size calculated in GBs
    t_size=$(archive_audit -v $uservsn $target | awk '{sum+=$7} END {print sum/1024/1024/1024}')
    n_inodes=$(sfind $target -vsn $uservsn | wc -l)
    n_dirs=$(sfind $target -type d -vsn $uservsn | wc -l)
    n_links=$(sfind $target -type l -vsn $uservsn | wc -l)
    n_files=$(archive_audit -v $uservsn $target | wc -l)
    n_cfiles=$n_files
    logmsg "     size: $t_size GB"
    logmsg "     inodes: $n_inodes"
    logmsg "     files: $n_files"
    logmsg "     files with copy ${copy}: $n_cfiles"
    logmsg "     dirs: $n_dirs"
    logmsg "     links: $n_links"
else
    fs_data=$(samfsdump -T -f /dev/null $target 2>&1 | egrep 'Files:|Directories:|Symbolic links:|Files w/checksums')
    n_files=$(echo "$fs_data" | egrep "Files:" | cut -d: -f2 | awk '{print $1}')
    n_dirs=$(echo "$fs_data" | egrep "Directories:" | cut -d: -f2 | awk '{print $1}')
    n_links=$(echo "$fs_data" | egrep "links:" | cut -d: -f2 | awk '{print $1}')
    n_inodes=$(($n_files+$n_dirs+$n_links))
    # target size calculated in GBs
    t_size=$(sdu -sk $target|awk '{print $1/1024/1024}')
    n_cfiles=$(sfind $target -type f -copy $copy | wc -l)
    logmsg "     size: $t_size GB"
    logmsg "     inodes: $n_inodes"
    logmsg "     files: $n_files"
    logmsg "     files with copy ${copy}: $n_cfiles"
    logmsg "     dirs: $n_dirs"
    logmsg "     links: $n_links"
fi
logmsg " "

# ------------------------------------------------------------ #
# Compile list of checksums from inodes.
# When this script was written, VSM only supported MD5 and a proprietary CRC.
# We assume MD5 is in use.
# ------------------------------------------------------------ #

all_inos_md5="${logdir}/all_inos_md5.txt"

# then sls -ERa $target|~root/bin/print_md5_li_from_sls.pl > ${all_inos_md5} &
if [ $copy -ne 1 ]
    then ~root/bin/print_csum_li_from_sls $target > ${all_inos_md5} &
else
    ~root/bin/print_csum_dk_from_sls $target > ${all_inos_md5} &
fi
sls_pid=$!
#logmsg "Compiling list of MD5 (ssum -a md5) checksums from VSMFS inodes (sls -E) in background (pid: ${sls_pid})..."

#logmsg "Generating \"archive_audit -c ${copy} `pwd`/${dir}\" data..."
aa_all="${logdir}/all_archive_audit.txt"
if [ $file != "null" ]
    then echo "grep string: $sam/$dir/$file"
    archive_audit -c $copy $dir | egrep "${sam}/${dir}/${file}$" > $aa_all
else
    archive_audit -c $copy $dir > $aa_all
fi
#logmsg "Complete"
#logmsg " "

#logmsg "Waiting for sls -ERa to finish.."
while ps -p $sls_pid > /dev/null; do sleep 1; done
#logmsg "        PID $sls_pid Complete!"
#logmsg " "

# ------------------------------------------------------------ #
# Now generate checksums for given copy-no and VSN (if applicable).
# ------------------------------------------------------------ #

#logmsg "Generating list of VSNs..."

while read nfiles vsn
do
    vsn_instructions="${logdir}/${vsn}-positions.txt"
    touch $vsn_instructions;

    if [ $uservsn != "undefined" ] && [ $uservsn != $vsn ]
    then continue
    fi

    size=0
    narcs=0
    if [ $copy -ne 1 ]
        then size=`egrep "^li ${vsn}" $aa_all | awk '{sum+=$7} END {print sum/1024/1024/1024}'`
	narcs=`egrep "^li $vsn" ${aa_all} |awk '{print $6}'|sed 's/\..*//'|sort|uniq|wc -l`
    else
        size=`egrep "^dk ${vsn}" $aa_all | awk '{sum+=$7} END {print sum/1024/1024/1024}'`
	narcs=`egrep "^dk ${vsn}" ${aa_all} |awk '{print $6}'|sed 's/\..*//'|sort|uniq|wc -l`
    fi
#    logmsg "VSN: $vsn # Files: ${nfiles} (${size} GB). # Archives: ${narcs}."

    # Get list of sorted positions.
    vsngrep="undefined"
    if [ $copy -ne 1 ]
        then vsngrep="^li ${vsn}"
    else vsngrep="^dk ${vsn}"
    fi

    egrep "${vsngrep}" $aa_all |awk '{print $6}'|sed 's/\..*//'| sort | uniq -c | while read cnt hexpos
    do
	if [ $copy -ne 1 ]
	    then echo "$cnt $hexpos `echo $((16#${hexpos}))`"
	else
	    # dkname is a simple c program that converts hex position (archive_audit output) to a disk-archive filename, e.g. "d3/f120"
	    echo "$cnt $hexpos `dkname $hexpos`"
	fi
    # Note: "dkpath" here is only relevant in disk-archive case. In tape case, ignored.
    done | sort -n -k3 | awk '{printf "%s %s %s\n", $1,$2,$3}' | while read count pos dkpath
    do
        # For each position (or dkpath)...
	if [ $copy -ne 1 ]
	then
	    echo "$count $pos $dkpath" >> $vsn_instructions
	    arsize=`egrep "^li $vsn" $aa_all | egrep " $pos\." | awk '{sum+=$7} END {print sum/1024/1024/1024}'`
	    # logmsg "    Creating request for $vsn:$pos -- reading $count files ($arsize GB)"
	else 
	    echo "$count $pos $dkpath" >> $vsn_instructions
	    arsize=`egrep "^dk $vsn" $aa_all | egrep " $pos\." | awk '{sum+=$7} END {print sum/1024/1024/1024}'`
	    # logmsg "    Checking ${count} files in ${vsn}:${dkpath} -- (${arsize} GB)"
	fi
    done

    #
    # Finished preparing list of archives for this VSN.
    #

    if [ $copy -ne 1 ]
    then joblimit=$joblimit_li
    elif [ $copy -eq 1 ]
    then joblimit=$joblimit_dk
    fi

    # Kick off a job to process this VSN.
    # First make sure we don't exceed the number of running jobs ($joblimit)
    if [ ${#rfix_pid_grep} -gt "0" ]
    then
      while [ $(ps -hp $rfix_pid_grep | wc -l) -gt $joblimit ]
      do
        sleep 5
      done
      # subsequent runs
      if [ $DEBUG -eq 1 ]
      then
          echo "DEBUG:  runfixity_vsn.sh $logdir $vsn $copy $nfiles $narcs $size $vsn_instructions &"
      fi
      runfixity_vsn.sh $logdir $vsn $copy $nfiles $narcs $size $vsn_instructions &
      rfix_pid_grep="$! $rfix_pid_grep"
        # remove stale pids from list
      rfix_pid_grep=$(ps -hp $rfix_pid_grep|awk '{print $1}'|xargs echo -n)
    else
      # first run
      if [ $DEBUG -eq 1 ]
      then
          echo "DEBUG:  runfixity_vsn.sh $logdir $vsn $copy $nfiles $narcs $size $vsn_instructions &"
      fi
      runfixity_vsn.sh $logdir $vsn $copy $nfiles $narcs $size $vsn_instructions &
      rfix_pid_grep="$!"
    fi
done < <(awk '{print $2}' $aa_all | sort | uniq -c)


# Final loop to wait for straggling runfixity_vsn.sh procs?

while [ $(ps -hp $rfix_pid_grep | wc -l) -gt "0" ]
do
  sleep 5
done

logmsg " ***  runfixity.sh COMPLETE!  ***"

t_missing_cksums=$(egrep -v '\-\-\-\-' ${logdir}/*missing_checksums.txt | wc -l | awk '{print $1}')
t_missing=$(egrep -v '\-\-\-\-' ${logdir}/*missing_files.txt* | wc -l | awk '{print $1}')
t_renamed=$(egrep -v '\-\-\-\-' ${logdir}/*renamed* | wc -l | awk '{print $1}')
t_bad=$(egrep -v '\-\-\-\-' ${logdir}/*bad* | wc -l | awk '{print $1}')
#t_symlinks=$(egrep -v '\-\-\-\-' ${logdir}/*symlinks.txt | wc -l | awk '{print $1}')
t_emptyfiles=$(egrep -v '\-\-\-\-' ${logdir}/*emptyfiles.txt | wc -l | awk '{print $1}')

echo "Totals:"

# Files missing a checksum in the inode is common
printf -v msg "%17s : %d" "Missing Checksums" $t_missing_cksums
logmsg "$msg"

# Files missing a copy is a serious problem. This should basically never happen.
printf -v msg "%17s : %d" "Missing Copies" $t_missing
logmsg "$msg"

# Files that are renamed (filename in inode is different than in archive) is common for certain collections.
# Eventually should probably be re-archived to keep filenames in sync.
printf -v msg "%17s : %d" "Renamed" $t_renamed
logmsg "$msg"

# Checksum mismatch is also a serious problem -- but why we run a fixity check.
printf -v msg "%17s : %d" "Bad Checksums" $t_bad
logmsg "$msg"

# Empty (zero-length) files can be a helpful data point -- esp when it provides reason for bad checksums
printf -v msg "%17s : %d" "Zero-length files" $t_emptyfiles
logmsg "$msg"
