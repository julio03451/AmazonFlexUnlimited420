# Flex Unlimited 420 + Script Dock #

## Automate searching and accepting Amazon Flex Driver jobs ##

This is an attempt to automate picking up Amazon Flex driver jobs. I attempted to automate this process for a client and it worked well. The only setup caveat is that you have to run the program on a machine connected to the Internet by wire; wireless isn't fast enough to compete with the dumb clickers that Flex drivers are fooled into paying for (https://www.cnbc.com/2020/02/09/amazon-flex-drivers-use-bots-to-get-more-work.html). These clickers require the drivers to stare at their phones all day long and watch the clicker 'ghost' click the "Refresh" button to search for jobs, but at a rate of 1000x of what they can do with their thumbs. This is stupid software that only the unknowledgeable will fall for; true software automates an entire process without any continous human intervention, know-how, or awareness. My ultimate goal was for any Amazon Flex driver to only pick up their phone to actually DO the jobs this program accepted on their behalf; they would never have to search for jobs again. 

**Note**: I reverse-engineered the Amazon Flex API by running Charles Proxy on my iPhone whilst doing a variety of things on the Flex app (e.g logging in, searching for jobs, accepting a job, declining a job). You can do the same if you need to update the reverse engineered API in this program.

**Disclaimer 1**: Run this program at your own risk. I am not responsible for Flex account termination or penalties imposed by Amazon as a result of using this program. 

**Disclaimer 2**: I tried to run this on a AWS server and it didn't work, possibly because Flex blocks all incoming connections from data centers to prevent large scale automation. But perhaps it'll work out of data centers not owned by AWS. 

## Usage ##

ALL DONE VIA Script_Dock.py just double click

0. You MUST have python 3 installed. Versions below 3 will not work.  
1. Clone the repo to the machine you will be using to run the program (machine should be connected to Internet by wire for best results).
2. Install dependencies using **pip**: `pip install -r requirements.txt`.
3. Double click **Script_Dock.py**, you will need to click **Start app** to go through the sign in steps. copy the link to a browser, sign in, and when you get to 'looking for something' copy the URL from the address bar back into the terminal
4. Click **GetServiceAreas**. This will pull your eligible stations, which you can use **Choose_Stations** to select the stations you want to filter for, then click generate. If you don't want to filter certain stations you can skip this.
5. Click **Settings**, and adjust to your liking, then click save. Optionally, setup SMS notifications of Amazon Flex job acceptances by filling out the `twilio` parameters in  Settings.
7. Optionally, you may also change the UserAgent the script is identifying as by clicking **Set_User_Agent**
8. Click **Start app** when you are ready. you can wait for it to run through it's refreshes or stop it early with **Stop app**



