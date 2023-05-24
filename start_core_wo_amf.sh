#!/bin/bash

./install/bin/open5gs-nrfd -d &
./install/bin/open5gs-scpd &
./install/bin/open5gs-amfd -d -t &
./install/bin/open5gs-smfd & 
./install/bin/open5gs-upfd & 
./install/bin/open5gs-ausfd -d& 
./install/bin/open5gs-udmd -d & 
./install/bin/open5gs-pcfd & 
./install/bin/open5gs-nssfd & 
./install/bin/open5gs-bsfd & 
./install/bin/open5gs-udrd -d & 
./install/bin/open5gs-mmed & 
./install/bin/open5gs-sgwcd & 
./install/bin/open5gs-sgwud & 
./install/bin/open5gs-hssd & 
./install/bin/open5gs-pcrfd & 
