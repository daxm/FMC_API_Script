# Update
These scripts work as is, but are definately in an "alpha" stage.

# File Summary
The fmcapi.py file provides an FMC class will issue API actions against an FMC.

Each "Roadshow#X" folder contains the scripts used in my Cisco FE Roadshow labs.  Their contents
should show you the general idea on how to use/interact with the fmcapi.py script.

# Important Note (AKA disclaimer)
There is little error checking in these scripts as of now as they work "good enough" for my purposes.

# fmcapi.py contents
In the FMC class there are subroutines for connecting to the FMC, POST/GET/PUT'ing to the FMC, as well as a set of subroutines to do the following:
* Create Security Zones
* Create Network Objects
* Create URL Objects
* Create Access Control Policies
* Create ACP Rules
* Add/Register FTD to FMC

Additionally, these subroutines that don't currently work:
* Modify FTD Physical Interfaces -- I think the issue is on the server side though.

# Wish List
* Improve error checking and reports especially for the API action functions (PUT/POST/GET).
* Subroutine for creating NAT Policies (no API function to reference yet)
* Subroutine for creating NAT Policy Rules (no API function to reference yet)
* Modify the Access Control Policy subroutine to build inheritance of ACPs (not supported in API yet.)
* Have subroutines use the BULK Deploy feature that was added to the API in v6.2.1
* Subrouting for creating/modifying Routing (no API function to reference yet)
