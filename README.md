# vsm-checksum-scripts

For some notes on usage: https://jhulibraries.atlassian.net/wiki/spaces/OPS/pages/1326153735/Verify+VSM+Content+By+Means+Of+Checksums

The `runfixity.sh` shell script takes a directory (of a VSM file-system) and a copy no. as arguments, and optionally a vsn to limit the scope to a particular vsn. It essentially builds a table of all the files under the given directory (including filename, checksum in the inode, vsn, and vsn position and offset). It then builds a similar table derived directly from the copy-tier (disk-archive or tape), calculating the checksums. Finally it compares the tables (keying on offset) and reports the results.

The `runfixity.sh` script depends on:
1. runfixity_vsn.sh
2. print_csum_from_sls.c (which is compiled to `print_csum_dk_from_sls` and `print_csum_li_from_sls`)
3. print_offset_cksum_from_tar.c (which compiles to `print_offset_cksum_from_tar`)

The `getbaginfo` program is a multi-threaded program that can verify a Bagit bag directly on the disk-archive. This is convenient for large (e.g TB-sized) bags that are not in the cache. Its purpose is to be efficient (reading directly from archival media) and performant (calculating checksums in parallel -- assuming there is more than one file in the bag).
