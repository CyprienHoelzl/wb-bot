#!/usr/bin/python3
# coding=UTF-8
"""
Created on Tue Nov  9 14:20:11 2021

Runs a bot for signing up to working bicycle campaigns

@author: Cyprien Hoelzl
"""
import requests
import datetime
import sched, time
import logging
import json
import getpass
from pathlib import Path
import argparse


CREDENTIALS_FILENAME = ".wb-bot.json"
CREDENTIALS_EMAIL = "email"
CREDENTIALS_PW = "password"

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)

ISSUES_URL = "https://github.com/CyprienHoelzl/wb-bot/issues"


#%% Depracation decorator
import functools
import inspect
import warnings
string_types = (type(b''), type(u''))

def deprecated(reason):
    """
    This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.
    """

    if isinstance(reason, string_types):

        # The @deprecated is used with a 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated("please, use another function")
        #    def old_function(x, y):
        #      pass

        def decorator(func1):

            if inspect.isclass(func1):
                fmt1 = "Call to deprecated class {name} ({reason})."
            else:
                fmt1 = "Call to deprecated function {name} ({reason})."

            @functools.wraps(func1)
            def new_func1(*args, **kwargs):
                warnings.simplefilter('always', DeprecationWarning)
                warnings.warn(
                    fmt1.format(name=func1.__name__, reason=reason),
                    category=DeprecationWarning,
                    stacklevel=2
                )
                warnings.simplefilter('default', DeprecationWarning)
                return func1(*args, **kwargs)

            return new_func1

        return decorator

    elif inspect.isclass(reason) or inspect.isfunction(reason):

        # The @deprecated is used without any 'reason'.
        #
        # .. code-block:: python
        #
        #    @deprecated
        #    def old_function(x, y):
        #      pass

        func2 = reason

        if inspect.isclass(func2):
            fmt2 = "Call to deprecated class {name}."
        else:
            fmt2 = "Call to deprecated function {name}."

        @functools.wraps(func2)
        def new_func2(*args, **kwargs):
            warnings.simplefilter('always', DeprecationWarning)
            warnings.warn(
                fmt2.format(name=func2.__name__),
                category=DeprecationWarning,
                stacklevel=2
            )
            warnings.simplefilter('default', DeprecationWarning)
            return func2(*args, **kwargs)

        return new_func2

    else:
        raise TypeError(repr(type(reason)))

#%% Function Definition
class WbBotException(Exception):
    pass
class CredentialsManager:
    def __init__(self, email, password, save_credentials):
        self.credentials = self.__load()
        if self.credentials is None:
            if email is None:
                raise WbBotException("Not all required credentials are supplied")

            logging.info("Loading credentials from arguments")
            if password is None:
                password = getpass.getpass("Organisation password:")

            self.credentials = {
                CREDENTIALS_EMAIL: email,
                CREDENTIALS_PW: password,
            }
        elif email is not None:
            logging.info(
                "Overwriting credentials loaded from local store with arguments"
            )
            if email is not None:
                self.credentials[CREDENTIALS_EMAIL] = email

            if password is None:
                password = getpass.getpass("Organisation password:")
            if password is not None and len(password) > 0:
                self.credentials[CREDENTIALS_PW] = password
        else:
            logging.info("Loaded credentials from local store")

        if save_credentials:
            logging.info("Storing credentials in local store")
            self.__store()

    def get(self):
        return self.credentials

    def __store(self):
        with open(CREDENTIALS_FILENAME, "w") as f:
            json.dump(
                self.credentials,
                f,
            )

    def __load(self):
        creds = Path(CREDENTIALS_FILENAME)
        if not creds.is_file():
            return None

        with open(CREDENTIALS_FILENAME, "r") as f:
            data = json.load(f)
            if (CREDENTIALS_EMAIL not in data
                or CREDENTIALS_PW not in data
            ):
                return None
            return data

class WbEnroller:
    def __init__(self, creds):
        """
        Initialize class

        Parameters
        ----------
        creds : credentials dictionary.

        Returns
        -------
        None.

        """
        self.creds = creds
        logging.info(
            "Summary:\n\tEmail: {}\n\tPassword: {}".format(
                self.creds[CREDENTIALS_EMAIL],
                "*" * len(self.creds[CREDENTIALS_PW]),
            )
        )
        self.logininfo = self.login().json()
        
    def login(self):
        """
        Login to Website

        Returns
        -------
        response : HTTPS request response

        """
        headers = {"authority": "api.workingbicycle.ch",
        "method": "POST",
        "path": "/login",
        "scheme": "https",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9,fr;q=0.8,de;q=0.7,sv;q=0.6,it;q=0.5,ja;q=0.4",
        "content-length": "61",
        "content-type": "application/json",
        "origin": "https://driver.workingbicycle.ch",
        "referer": "https://driver.workingbicycle.ch/",
        "sec-ch-ua": """"Google Chrome";v="111", "Chromium";v="111", ";Not A Brand";v="99""" + '"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
        }
        username = self.creds[CREDENTIALS_EMAIL]
        password = self.creds[CREDENTIALS_PW]
        query = {"email": username, 
                 "password": password}
        response = requests.post('https://api.workingbicycle.ch/login', 
                               headers=headers, json=query)
        return response
    def getActiveCampaignsDashboardData(self):
        """
        Get list of active campaigns

        Returns
        -------
        response : HTTP response.

        """
        headers = {"authority": "api.workingbicycle.ch",
        "method": "GET",
        "path": "/campaigns/available?itemsPerPage=10&page=1",
        "scheme": "https",
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9,fr;q=0.8,de;q=0.7,sv;q=0.6,it;q=0.5,ja;q=0.4",
        "authorization": "Bearer " + self.logininfo['token'], # token valid 8 hours
        "if-none-match": 'W/"0e97e7afe709c72674eaf147fc3b7e54"', # check if this needs to be updated
        "origin": "https://driver.workingbicycle.ch",
        "referer": "https://driver.workingbicycle.ch/",
        "sec-ch-ua": """"Google Chrome";v="111", "Chromium";v="111", ";Not A Brand";v="99""" + '"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
        }
        response = requests.get('https://api.workingbicycle.ch/campaigns/available?itemsPerPage=10&page=1', 
                               headers=headers)
        return response
    
    def registerfornotifications(self,driverid,campaignid):
        """
        Register for notifications

        Parameters
        ----------
        driverid : id of driver.
        campaignid : id of campaign.

        Returns
        -------
        response : HTTP response.

        """
        headers = {"authority": "api.workingbicycle.ch",
                    "method": "POST",
                    "path": "/campaign_waiting_list_registrations",
                    "scheme": "https",
                    "accept": "application/json, text/plain, */*",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "en-US,en;q=0.9,fr;q=0.8,de;q=0.7,sv;q=0.6,it;q=0.5,ja;q=0.4",
                    "authorization": "Bearer " + self.logininfo['token'],
                    "content-length": "119",
                    "content-type": "application/json",
                    "origin": "https://www.driver.workingbicycle.ch",
                    "referer": "https://www.driver.workingbicycle.ch/",
                    "sec-ch-ua": """"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99""" + '"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Windows",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
                    }    
        query = {"driver": driverid, 
                 "campaign":campaignid}       
        
        
        response = requests.post('https://api.workingbicycle.ch/campaign_waiting_list_registrations', 
                   headers=headers, json=query)
        return response
    
    def registerforcampaign(self,campaignid,driverid):
        """
        Register for campaign

        Parameters
        ----------
        campaignid : id of campaign.
        driverid : id of driver.

        Returns
        -------
        response : HTTP response.

        """
        headers = {"authority": "api.workingbicycle.ch",
                    "method": "POST",
                    "path": "/campaign_registrations",
                    "scheme": "https",
                    "accept": "application/json, text/plain, */*",
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": "en-US,en;q=0.9,fr;q=0.8,de;q=0.7,sv;q=0.6,it;q=0.5,ja;q=0.4",
                    "authorization": "Bearer " + self.logininfo['token'],
                    "content-length": "139",
                    "content-type": "application/json",
                    "origin": "https://www.driver.workingbicycle.ch",
                    "referer": "https://www.driver.workingbicycle.ch/",
                    "sec-ch-ua": """"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99""" + '"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Windows",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
                    }          
        query = {"driver": driverid, 
                 "campaign":campaignid
                 }   
        response = requests.post('https://api.workingbicycle.ch/campaign_registrations', 
                               headers=headers,  json=query)
        return response
    
    def signup_for_campaign_or_for_notification(self,campaigns):
        """
        Signup or subscribe to notifications

        Parameters
        ----------
        campaigns : fetched campaigns.

        Raises
        ------
        WbBotException
            Stops in case of error.

        Returns
        -------
        None.

        """
        # campaignNotificationSubscribers = campaigns['driver']['campaignNotificationSubscribers']
        new_campaigns = campaigns['hydra:member']
        # registeredCampaigns = campaigns['driver']['registeredCampaigns']
        driverid = self.logininfo['user']['driver']['@id']
        # Windows of existing campaigns
        rg = []
        # for rc in registeredCampaigns: 
        #     campaignStartDate = datetime.datetime.fromisoformat(rc['campaign']['campaignStartDate'])
        #     campaignEndDate = datetime.datetime.fromisoformat(rc['campaign']['campaignEndDate'])
        #     rg.append((campaignStartDate,campaignEndDate))
        for campaign in new_campaigns:
            campaignid = campaign['@id']
            boolAvailableSpot = campaign['fullyBooked']==False
            boolNoWaitingList = campaign['isOnWaitingList']==False
            # boolNotOnTheStreet = campaign['campaignAlreadyOnTheStreet']==False
            # boolNotRegisteredOnCampaign = campaign['isDriverRegisteredOnCampaign']==False
            campaignStartDate = datetime.datetime.fromisoformat(campaign['actualStartDate'])
            campaignEndDate = datetime.datetime.fromisoformat(campaign['actualEndDate'])
            # only sign up if not overlapping
            doesnotoverlap_existingcampaign = True
            if len(rg)>0:
                for s,e in rg:
                    if ((campaignStartDate>=e) | (campaignEndDate<=s))==False:
                        doesnotoverlap_existingcampaign =False
            # sign up for campaign or activate notification for empty slots
            response = None
            if boolAvailableSpot & doesnotoverlap_existingcampaign:#& boolNotOnTheStreet & boolNotRegisteredOnCampaign:
                response = self.registerforcampaign(campaignid,driverid)
                if response.status_code == 201:
                    logging.info('Registered for driving: {}'.format(campaignid))
                    rg.append((datetime.datetime.fromisoformat(campaign['actualStartDate']),
                               datetime.datetime.fromisoformat(campaign['actualEndDate'])))
                else:
                    logging.error('Error: {}, \t{}'.format(response.status_code,json.JSONDecoder().decode(response.text)['message']))
                    raise WbBotException('Error registering: {}'.format(e))
            else:
                #Sign up for notification if not already signed up
                if boolNoWaitingList:           
                    response = self.registerfornotifications(driverid,campaignid)
                    if response.status_code == 201:
                        logging.info('Registered for notifications: {}'.format(campaignid))   
                    else:
                        logging.error('Error: {}, \t{}'.format(response.status_code,json.JSONDecoder().decode(response.text)))
                        raise WbBotException('Error registering: {}'.format(e))

def signup_wb(s,creds,timewindow): 
    """
    Scheduled Signup to working bicycle campaign

    """
    logging.info("Running signup scheduler...") 
    try:
        #% Login
        wb_enroller = WbEnroller(creds)
        # Get currently active campaigns
        response =  wb_enroller.getActiveCampaignsDashboardData()
        campaigns =response.json()
        # Sign up for open campaign
        wb_enroller.signup_for_campaign_or_for_notification(campaigns)
        # If signup completed, start a new run to scheduler (no break occurs)
        s.enter(timewindow , 1, signup_wb, (s,creds,timewindow))
    except Exception as e:
        logging.error(e)
        raise WbBotException('Exception: {}'.format(e))
#%% Schedule running code every timewindow
def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-e", "--email", type=str, help="Email")
    parser.add_argument("-p", "--password", type=str, help="Password")
    parser.add_argument("-s", "--schedule", type=int, default = 150, help="Schedule WB request every 150 (default value) seconds")
    parser.add_argument(
        "--save-credentials",
        default=False,
        action="store_true",
        help="Store your login credentials locally and reused them on the next run",
    )

    args = parser.parse_args()

    creds = None
    try:
        creds = CredentialsManager(
            args.email, args.password, args.save_credentials
        ).get()
    except WbBotException as e:
        logging.error(e)
        exit(1)
        
    #% Login
    wb_enroller = WbEnroller(creds)
    # Get currently active campaigns
    response =  wb_enroller.getActiveCampaignsDashboardData()
    campaigns =response.json()
    # Sign up for open campaign
    wb_enroller.signup_for_campaign_or_for_notification(campaigns)        
        
    logging.info('Starting Script')
    timewindow = args.schedule
    s = sched.scheduler(time.time, time.sleep)
    s.enter(timewindow , 1, signup_wb, (s,creds,timewindow))
    s.run()

if __name__ == "__main__":
    main()







