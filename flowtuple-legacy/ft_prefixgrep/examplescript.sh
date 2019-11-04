#!/bin/bash

# This example script will search for all flowtuples matching the prefix
# 1.2.3.0/24 in all flowtuple files for the year 2019, starting with
# the most recent day and working backwards.
#
# The flowtuple files are pulled from the UCSD-NT object store using
# swift. This script requires you to have previously configured your
# swift credentials in the terminal that will be running the script.
#
# The output files will be written to /home/limbo/flowtuples/
#
# The script uses gnu parallel to process 6 flowtuple files concurrently.
#
# Author: Shane Alcock

BASECOL=data-telescope-meta-flowtuple

MONTHS=($(seq 12 -1 1))
YEARS=(2019)
DAYS=($(seq 31 -1 1))

# Function: processes a single flowtuple file using ft_prefixgrep. Output is
# written to what should be a unique file name.
# The argument to this function should be the full swift filename for the
# flowtuple file (as given by 'swift list').
procfile() {
        BIN=/home/limbo/ft_prefixgrep/ft_prefixgrep
        INTBASECOL=data-telescope-meta-flowtuple
        BASEOUTPUT=/home/limbo/flowtuples
        PREFIX=1.2.3.0
        BITMASK=24

        # Get the timestamp from the file name
        echo ${1}
        unixts="$(basename -- ${1} | awk -F '[.]' '{print $2}')"

        # Run ft_prefixgrep
        ${BIN} -p ${PREFIX}/${BITMASK} -s -o ${BASEOUTPUT}/${unixts}-${PREFIX}-${BITMASK}.ftuples -f swift://${INTBASECOL}/${1}
}

# Functions must be exported to be used with gnu parallel
export -f procfile

for y in ${YEARS[@]}; do
        for m in ${MONTHS[@]}; do
                for d in ${DAYS[@]}; do
                       # Get the list of flowtuple files for the given day
                       filelist=`swift list $BASECOL -d / -p "datasource=ucsd-nt/year=${y}/month=${m}/day=${d}/"`
                       echo ${y}/${m}/${d}

                       # Use gnu parallel to process these files, 6 at a time
                       if [[ ${filelist} = *[!\ ]* ]]; then
                               parallel --trim lr --no-run-if-empty -j 6 procfile ::: ${filelist}
                       fi

                 done
        done
done
