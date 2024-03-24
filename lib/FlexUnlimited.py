from lib.Offer import Offer
from lib.Log import Log
from lib.Chain import Chain
from typing import Dict, List, Tuple
import requests, time, sys, json, uuid, traceback
from requests.models import Response
from datetime import datetime
from prettytable import PrettyTable
from urllib.parse import unquote, urlparse, parse_qs
import base64, hashlib, hmac, gzip, secrets, pyaes
from pbkdf2 import PBKDF2
from urllib.parse import unquote, urlparse, parse_qs, urlencode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

try:
  from twilio.rest import Client
except:
  pass

APP_NAME = "com.amazon.rabbit"
APP_VERSION = "303338310"
DEVICE_NAME = "Le X522"
MANUFACTURER = "LeMobile"
DEVICE_TYPE = "A1MPSLFC7L5AFK"
OS_VERSION = "LeEco/Le2_NA/le_s2_na:6.0.1/IFXNAOP5801910272S/61:user/release-keys"
MARKETPLACE = "ATVPDKIKX0DER"
ANDROID_FLEX_VERSION = "3.104.1.39.0"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G988N Build/NRD90M)" # Put your user agent here
REFRESH_SIGNATURE_INTERVAL = 5 # Every 5 minutes

class FlexUnlimited:
  allHeaders: Dict[str, Dict] = {
    "AmazonApiRequest": {
      "User-Agent": USER_AGENT,
      "Content-Type": "application/json",
      "Accept-Charset": "utf-8",
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "Connection": "keep-alive",
      "Accept": "*/*",
      "Accept-Language": "en-US"
    },
    "FlexCapacityRequest": {
      "x-amz-access-token": None,
      "Accept-Encoding": "gzip, deflate, br",
      "x-flex-instance-id": None,
      "Accept-Language": "en-US",
      "Content-Type": "application/json",
      "User-Agent": f"{USER_AGENT} RabbitAndroid/{ANDROID_FLEX_VERSION}",
      "Connection": "keep-alive",
      'X-Amzn-RequestId': None,
      'X-Flex-Client-Time': None,
      "x-amzn-marketplace-id": MARKETPLACE
    }
  }
  routes = {
    "GetOffers": "https://flex-capacity-na.amazon.com/GetOffersForProviderPost",
    "AcceptOffer": "https://flex-capacity-na.amazon.com/AcceptOffer",
    "GetAuthToken": "https://api.amazon.com/auth/register",
    "RequestNewAccessToken": "https://api.amazon.com/auth/token",
    "ForfeitOffer": "https://flex-capacity-na.amazon.com/schedule/blocks/",
    "GetEligibleServiceAreas": "https://flex-capacity-na.amazon.com/eligibleServiceAreas",
    "GetOfferFiltersOptions": "https://flex-capacity-na.amazon.com/getOfferFiltersOptions"
  }

  def __init__(self) -> None:
    try:
      with open("config.json") as configFile:
        config = json.load(configFile)
        self.desiredWarehouses = config["desiredWarehouses"] if len(config["desiredWarehouses"]) >= 1 else []  # list of warehouse ids
        self.minBlockRate = config["minBlockRate"]
        self.minPayRatePerHour = config["minPayRatePerHour"]
        self.arrivalBuffer = config["arrivalBuffer"]  # arrival buffer in minutes
        self.desiredStartTime = config["desiredStartTime"]  # start time in military time
        self.desiredEndTime = config["desiredEndTime"]  # end time in military time
        self.desiredWeekdays = set()
        self.retryLimit = config["retryLimit"]  # number of jobs retrieval requests to perform
        self.refreshInterval = config["refreshInterval"]  # sets delay in between getOffers requests
        self.twilioFromNumber = config["twilioFromNumber"]
        self.twilioToNumber = config["twilioToNumber"]
        self.__retryCount = 0
        self.__rate_limit_number = 1
        self.__acceptedOffers = []
        self.__startTimestamp = time.time()
        self.__requestHeaders = FlexUnlimited.allHeaders.get("FlexCapacityRequest")
        self.__acceptHeaders = self.__requestHeaders.copy()
        self.__accept_headers_last_updated = 0
        self.refreshToken = config["refreshToken"]
        self.accessToken = config["accessToken"]
        self.android_device_id = config["deviceId"]
        self.device_serial = config["deviceSerial"]
        self.flex_instance_id = config["flexInstanceId"]
        self.key_id = config["keyId"]
        self.key_id_expiration = config["keyIdExpiration"]
        self.session = requests.Session()
        
        desiredWeekdays = config["desiredWeekdays"]

        twilioAcctSid = config["twilioAcctSid"]
        twilioAuthToken = config["twilioAuthToken"]
        
        self.private_key_str = config["privateAttestationKey"]

    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()

    if twilioAcctSid != "" and twilioAuthToken != "" and self.twilioFromNumber != "" and self.twilioToNumber != "":
      self.twilioClient = Client(twilioAcctSid, twilioAuthToken)
    else:
      self.twilioClient = None
    
    self.__setDesiredWeekdays(desiredWeekdays)

    if any(not x for x in [self.refreshToken, self.android_device_id, self.device_serial, self.flex_instance_id]):
      self.__registerAccount()

    self.__requestHeaders["x-amz-access-token"] = self.accessToken
    self.__acceptHeaders["x-amz-access-token"] = self.accessToken
    self.__requestHeaders["x-flex-instance-id"] = self.flex_instance_id
    self.__acceptHeaders["x-flex-instance-id"] = self.flex_instance_id
    self.__updateFlexHeaders(self.__requestHeaders)
    self.__updateFlexHeaders(self.__acceptHeaders)
    self.serviceAreaIds = self.__getEligibleServiceAreas()
    self.__offersRequestBody = {
      "apiVersion": "V2",
      "filters": {
        "serviceAreaFilter": self.desiredWarehouses,
        "timeFilter": {"endTime": self.desiredEndTime, "startTime": self.desiredStartTime}
      },
      "serviceAreaIds": self.serviceAreaIds
    }

    if not self.key_id or self.key_id_expiration is None or (int(time.time() * 1000) > int(self.key_id_expiration)):
      self.get_key_id()
    
  def __updateFlexHeaders(self, headers: Dict):
    headers["X-Flex-Client-Time"] = self.__getFlexClientTime()
    headers["X-Amzn-RequestId"] = self.__generate_uuid4()
    
  def __setDesiredWeekdays(self, desiredWeekdays: List[str]):
    weekdayMap = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
    if len(desiredWeekdays) == 0:
      self.desiredWeekdays = None
    else:
      for day in desiredWeekdays:
        dayAbbreviated = day[:3].lower()
        if dayAbbreviated not in weekdayMap:
          print("Weekday '" + day + "' is misspelled. Please correct config.json file and restart program.")
          exit()
        self.desiredWeekdays.add(weekdayMap[dayAbbreviated])
      if len(self.desiredWeekdays) == 7:
        self.desiredWeekdays = None
    
  def __generate_device(self):
    self.device_serial = secrets.token_hex(16)
    self.android_device_id = secrets.token_hex(8)
    
  def __generate_client_id(self) -> str:
    device_type = "#" + DEVICE_TYPE
    client_id = (self.device_serial.encode() + device_type.encode()).hex()
    return client_id
        
  def __generate_challenge_link(self) -> Tuple[str, str]:
    self.__generate_device()
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    client_id = self.__generate_client_id()
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=')
    oauth_params = {
        "openid.oa2.response_type": "code",
        "openid.oa2.code_challenge_method": "S256",
        "openid.oa2.code_challenge": code_challenge,
        "openid.return_to": "https://www.amazon.com/ap/maplanding",
        "openid.assoc_handle": "amzn_device_na",
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "pageId": "amzn_device_na",
        "accountStatusPolicy": "P1",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.mode": "checkid_setup",
        "openid.ns.oa2": "http://www.amazon.com/ap/ext/oauth/2",
        "openid.oa2.client_id": f"device:{client_id}",
        "openid.ns.pape": "http://specs.openid.net/extensions/pape/1.0",
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.pape.max_auth_age": "0",
        "openid.oa2.scope": "device_auth_access",
        "forceCaptcha": "true",
        "use_global_authentication": "false"
    }
    challenge_link = f"https://www.amazon.com/ap/signin?{urlencode(oauth_params)}"
    return challenge_link, code_verifier

  def __registerAccount(self):
    link, code_verifier = self.__generate_challenge_link()
    print("Link: " + link)
    maplanding_url = input("Open the previous link (make sure to copy the entire link) in a browser, sign in, and enter the entire resulting URL here:\n")
    parsed_query = parse_qs(urlparse(maplanding_url).query)
    authorization_code = unquote(parsed_query['openid.oa2.authorization_code'][0])
    client_id = self.__generate_client_id()
    amazon_reg_data = {
      "auth_data": {
        "client_id": client_id,
        "authorization_code": authorization_code,
        "code_verifier": code_verifier,
        "code_algorithm": "SHA-256",
        "client_domain": "DeviceLegacy"
      },
      "cookies": {
        "domain": ".amazon.com",
        "website_cookies": []
      },
      "device_metadata": {
        "android_id": self.android_device_id,
        "device_os_family": "android",
        "device_serial": self.device_serial,
        "device_type": DEVICE_TYPE,
        "manufacturer": MANUFACTURER,
        "model": DEVICE_NAME,
        "os_version": "33",
        "product": DEVICE_NAME
      },
      "registration_data": {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "device_model": DEVICE_NAME,
        "device_serial": self.android_device_id,
        "device_type": DEVICE_TYPE,
        "domain": "Device",
        "os_version": OS_VERSION,
        "software_version": "130050002"
      },
      "requested_extensions": [
        "device_info",
        "customer_info"
      ],
      "requested_token_type": [
        "bearer",
        "mac_dms",
        "store_authentication_cookie",
        "website_cookies"
      ],
      "user_context_map": {
        "frc": self.__generate_frc(self.android_device_id)
      }
    }
    res = self.session.post(FlexUnlimited.routes.get("GetAuthToken"), json=amazon_reg_data, headers=self.allHeaders.get("AmazonApiRequest"), verify=True)
    if res.status_code != 200:
        print("login failed")
        exit(1)
    res = res.json()
    tokens = res['response']['success']['tokens']['bearer']
    self.accessToken = tokens['access_token']
    self.refreshToken = tokens['refresh_token']
    self.flex_instance_id = self.__generate_uuid4()
    print("Displaying refresh token in case config file fails to save tokens.")
    print("If it fails, copy the refresh token into the config file manually.")
    print("Refresh token: " + self.refreshToken)
    self.__update_config_file({
        "accessToken": self.accessToken,
        "refreshToken": self.refreshToken,
        "deviceId": self.android_device_id,
        "deviceSerial": self.device_serial,
        "flexInstanceId": self.flex_instance_id
    })
    print("registration successful")

  @staticmethod
  def __generate_frc(device_id):
    """
    Helper method for the register function. Generates user context map.
    """
    cookies = json.dumps({
      "ApplicationName": APP_NAME,
      "ApplicationVersion": APP_VERSION,
      "DeviceLanguage": "en",
      "DeviceName": DEVICE_NAME,
      "DeviceOSVersion": OS_VERSION,
      "IpAddress": requests.get('https://api.ipify.org').text,
      "ScreenHeightPixels": "1920",
      "ScreenWidthPixels": "1280",
      "TimeZone": "00:00",
    })
    compressed = gzip.compress(cookies.encode())
    key = PBKDF2(device_id, b"AES/CBC/PKCS7Padding").read(32)
    iv = secrets.token_bytes(16)
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = encrypter.feed(compressed)
    ciphertext += encrypter.feed()
    hmac_ = hmac.new(PBKDF2(device_id, b"HmacSHA256").read(32), iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\0" + hmac_[:8] + iv + ciphertext).decode()

  def __getFlexAccessToken(self):
    data = {
      "app_name": APP_NAME,
      "app_version": APP_VERSION,
      "source_token_type": "refresh_token",
      "source_token": self.refreshToken,
      "requested_token_type": "access_token",
    }
    headers = {
      "User-Agent": USER_AGENT,
      "x-amzn-identity-auth-domain": "api.amazon.com",
    }
    res = self.session.post(FlexUnlimited.routes.get("RequestNewAccessToken"), json=data, headers=headers).json()
    self.accessToken = res['access_token']
    self.__update_config_file({"accessToken": self.accessToken})
    self.__requestHeaders["x-amz-access-token"] = self.accessToken
    self.__acceptHeaders["x-amz-access-token"] = self.accessToken
    
  @staticmethod
  def create_attestation_key() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key
  
  @staticmethod
  def serialize_and_encode_keys(private_key: ec.EllipticCurvePrivateKey) -> Tuple[str]:
    serialized_private_key = FlexUnlimited.serialize_private_key(private_key)
    b64_encoded_private_key = FlexUnlimited.encode_key(serialized_private_key)
    return b64_encoded_private_key
  
  @staticmethod
  def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
  
  @staticmethod
  def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.private_bytes(
      encoding=serialization.Encoding.DER,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
    )
  
  @staticmethod
  def encode_key(serialized_key: bytes) -> str:
    return base64.b64encode(serialized_key).decode()

  @staticmethod
  def load_attestation_private_key(private_key: str) -> ec.EllipticCurvePrivateKey:
    decoded_private_key = base64.b64decode(private_key)
    loaded_private_key = serialization.load_der_private_key(decoded_private_key, password=None, backend=default_backend())
    return loaded_private_key
  
  @staticmethod
  def __generate_uuid4() -> str:
    """
    Returns Amazon formatted timestamp as string
    """
    return str(uuid.uuid4())
  
  @staticmethod
  def __getFlexClientTime() -> str:
    return str(round(time.time() * 1000))
  
  @staticmethod
  def print_request_debug_info(response: requests.Response):
    try:
      debug_info = response.json()
    except:
      debug_info = response.text
    Log.error(debug_info)
  
  def sign_request(self, endpoint: str) -> dict:
    nonce = self.__getFlexClientTime()
    signature_params = f'("@path" "x-amzn-marketplace-id" "user-agent");created={nonce};nonce="{nonce}";alg="ecdsa-p256-sha256";keyid="{self.key_id}"'
    message_parts = [
      f"\"@path\": {endpoint}",
      f"\"x-amzn-marketplace-id\": {MARKETPLACE}",
      f"\"user-agent\": {USER_AGENT} RabbitAndroid/{ANDROID_FLEX_VERSION}",
      f"\"@signature-params\": {signature_params}"
    ]
    message = '\n'.join(message_parts)
    self.private_key = self.load_attestation_private_key(self.private_key_str)
    signature = self.private_key.sign(message.encode('utf-8'),ec.ECDSA(hashes.SHA256()))
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    signature_headers = {
      "Signature-Input": f"x-amzn-attest={signature_params}",
      "Signature": f"x-amzn-attest=:{encoded_signature}:"
    } 
    return signature_headers
  
  def register_attestation(self, cert_chain):
    headers = {
      'x-amz-access-token': self.accessToken,
      'User-Agent': f"{USER_AGENT} RabbitAndroid/{ANDROID_FLEX_VERSION}",
      'X-Flex-Client-Time': self.__getFlexClientTime(),
      'x-flex-instance-id': self.flex_instance_id,
      'Content-Type': 'application/json',
      'X-Amzn-RequestId': self.__generate_uuid4(),
      'Connection': 'Keep-Alive',
      'Accept': 'application/json',
      'X-Amzn-Identity-Auth-Domain': '.amazon.com',
      'x-amzn-marketplace-id': MARKETPLACE
    }
    data = {
      "deviceId": self.android_device_id,
      'keyAttestation': cert_chain,
    }

    base_url = "https://prod.us-east-1.api.app-attestation.last-mile.amazon.dev/"
    url = f"{base_url}v1/android/register-attestation"
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      self.__updateFlexHeaders(headers)
      headers["x-amz-access-token"] = self.accessToken
      response = requests.post(url, headers=headers, json=data)
    if response.status_code != 200:
      print(f"Error sending request to register-attestation. Status code: {response.status_code}")
      self.print_request_debug_info(response)
      sys.exit()
    response_json = response.json()
    key_id: str = response_json.get('keyId')
    key_id_expiration: int = response_json.get('expiration', 0)

    return key_id, key_id_expiration
  
  @staticmethod
  def __update_config_file(key_pairs: dict):
    try:
      with open("config.json", "r+") as configFile:
        config = json.load(configFile)
        for key in key_pairs:
          config[key] = key_pairs[key]
        configFile.seek(0)
        json.dump(config, configFile, indent=2)
        configFile.truncate()
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()

  def __getEligibleServiceAreas(self):
    self.__updateFlexHeaders(self.__requestHeaders)
    response = self.session.get(
      FlexUnlimited.routes.get("GetEligibleServiceAreas"),
      headers=self.__requestHeaders)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      self.__updateFlexHeaders(self.__requestHeaders)
      response = self.session.get(
        FlexUnlimited.routes.get("GetEligibleServiceAreas"),
        headers=self.__requestHeaders
      )
    return response.json().get("serviceAreaIds")

  def getAllServiceAreas(self):
    self.__updateFlexHeaders(self.__requestHeaders)
    response = self.session.get(
      FlexUnlimited.routes.get("GetOfferFiltersOptions"),
      headers=self.__requestHeaders
      )
    if response.status_code == 403:
      self.__getFlexAccessToken()
      self.__updateFlexHeaders(self.__requestHeaders)
      response = self.session.get(
        FlexUnlimited.routes.get("GetOfferFiltersOptions"),
        headers=self.__requestHeaders
      )

    serviceAreaPoolList = response.json().get("serviceAreaPoolList")
    serviceAreasTable = PrettyTable()
    serviceAreasTable.field_names = ["Service Area Name", "Service Area ID"]
    for serviceArea in serviceAreaPoolList:
      serviceAreasTable.add_row([serviceArea["serviceAreaName"], serviceArea["serviceAreaId"]])
    return serviceAreasTable

  def __getOffers(self) -> Response:
    """
    Get job offers.
    
    Returns:
    Offers response object
    """
    self.__updateFlexHeaders(self.__requestHeaders)
    response = self.session.post(
      FlexUnlimited.routes.get("GetOffers"),
      headers=self.__requestHeaders,
      json=self.__offersRequestBody)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      self.__updateFlexHeaders(self.__requestHeaders)
      response = self.session.post(
        FlexUnlimited.routes.get("GetOffers"),
        headers=self.__requestHeaders,
        json=self.__offersRequestBody)
    return response

  def __acceptOffer(self, offer: Offer):
    self.__updateFlexHeaders(self.__acceptHeaders)
    request = self.session.post(FlexUnlimited.routes.get("AcceptOffer"), headers=self.__acceptHeaders, json={"offerId": offer.id})

    if request.status_code == 403:
      self.__getFlexAccessToken()
      self.__updateFlexHeaders(self.__acceptHeaders)
      self.sign_accept_headers()
      request = self.session.post(
        FlexUnlimited.routes.get("AcceptOffer"),
        headers=self.__acceptHeaders,
        json={"offerId": offer.id})
      
    if request.status_code == 420:
      self.register_attestation()
      self.__updateFlexHeaders(self.__acceptHeaders)
      self.sign_accept_headers()
      request = self.session.post(
        FlexUnlimited.routes.get("AcceptOffer"),
        headers=self.__acceptHeaders,
        json={"offerId": offer.id})

    if request.status_code == 200:
      self.__acceptedOffers.append(offer)
      if self.twilioClient is not None:
        self.twilioClient.messages.create(
          to=self.twilioToNumber,
          from_=self.twilioFromNumber,
          body=offer.toString())
      Log.info(f"Successfully accepted an offer.")
    elif request.status_code == 410:
      Log.info(f"Offer already taken.")
    elif request.status_code == 307:
      Log.info(f"A captcha was required to accept an offer.")
      sys.exit()
    else:
      Log.error(f"Unable to accept an offer. Request returned status code {request.status_code}")

  def __processOffer(self, offer: Offer):
    if offer.hidden:
      return
      
    if self.desiredWeekdays:
      if offer.weekday not in self.desiredWeekdays:
        return

    if self.minBlockRate:
      if offer.blockRate < self.minBlockRate:
        return

    if self.minPayRatePerHour:
      if offer.ratePerHour < self.minPayRatePerHour:
        return

    if self.arrivalBuffer:
      deltaTime = (offer.expirationDate - datetime.now()).seconds / 60
      if deltaTime < self.arrivalBuffer:
        return

    self.__acceptOffer(offer)
    self.sign_accept_headers()

  def get_nonce(self, device_id):
      headers = {
        'x-amz-access-token': self.accessToken,
        'User-Agent': f"{USER_AGENT} RabbitAndroid/{ANDROID_FLEX_VERSION}",
        'X-Flex-Client-Time': self.__getFlexClientTime(),
        'x-flex-instance-id': self.flex_instance_id,
        'Content-Type': 'application/json',
        'X-Amzn-RequestId': self.__generate_uuid4()
      }
      request = requests.get(
          'https://prod.us-east-1.api.app-attestation.last-mile.amazon.dev/v1/nonce/id/' + device_id,
          headers=headers
      )
      return request.json()['nonce']

  def get_key_id(self):
    device_id = self.android_device_id

    nonce_base64 = self.get_nonce(device_id)
    nonce = base64.b64decode(nonce_base64).decode('utf-8')

    certs, private_key = Chain.get_chain(nonce)

    self.private_key_str = self.serialize_and_encode_keys(private_key)
    self.__update_config_file({
        "privateAttestationKey": self.private_key_str
      })
    
    self.key_id, self.key_id_expiration = self.register_attestation(cert_chain=certs)
    self.__update_config_file({
      "keyId": self.key_id,
      "keyIdExpiration": self.key_id_expiration
    })
    
  def sign_accept_headers(self):
    signature_headers = self.sign_request("/AcceptOffer")
    self.__acceptHeaders.update(signature_headers)
    self.__accept_headers_last_updated = time.time()

  def run(self):
    Log.info("Starting job search...")
    while self.__retryCount < self.retryLimit:
      if not self.__retryCount % 50:
        print(self.__retryCount, 'requests attempted\n\n')
      if self.__accept_headers_last_updated < time.time() - REFRESH_SIGNATURE_INTERVAL * 60:
        self.sign_accept_headers()
      offersResponse = self.__getOffers()
      if offersResponse.status_code == 200:
        currentOffers = offersResponse.json().get("offerList")
        currentOffers.sort(key=lambda pay: int(pay['rateInfo']['priceAmount']), reverse=True)
        for offer in currentOffers:
          offerResponseObject = Offer(offerResponseObject=offer)
          self.__processOffer(offerResponseObject)
        self.__retryCount += 1
      elif offersResponse.status_code == 400:
        minutes_to_wait = 30 * self.__rate_limit_number
        Log.info("Rate limit reached. Waiting for " + str(minutes_to_wait) + " minutes.")
        time.sleep(minutes_to_wait * 60)
        if self.__rate_limit_number < 4:
          self.__rate_limit_number += 1
        else:
          self.__rate_limit_number = 1
        Log.info("Resuming search.")
      elif offersResponse.status_code >= 500:
        Log.error("Amazon server error")
        pass
      else:
        self.print_request_debug_info(offersResponse)
        break
      time.sleep(self.refreshInterval)
    Log.info("Job search cycle ending...")
    Log.info(f"Accepted {len(self.__acceptedOffers)} offers in {time.time() - self.__startTimestamp} seconds")
