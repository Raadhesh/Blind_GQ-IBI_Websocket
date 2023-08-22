import asyncio
import websockets
import json

from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
from myFunctions import *

# Get Parameters N,e,d.
# N,e are the public parameters that will be shared while d is kept secret and known only to the server.
(N, e, d) = setupRSA(1024)
replyPublicParamJSON = {
    "response": "Public Parameters",
    "N_hex": hex_from_int(N),
    "e_hex": hex_from_int(e)
}

# Default reply if no process takes place
defaultReplyJSON = {
    "response": "ERROR",
    "message": "Default Reply"
}

async def handler(websocket, path):
    while True:
        try:
            print("\n\n")
            receiveData = await websocket.recv()
            replyJSON = defaultReplyJSON
            
            # testData string of python client
            testDataJSON = defaultReplyJSON

            data = json.loads(receiveData)
            
            if str(data["request"]) == "Public Parameters":
                print("\n\nPublic Parameters Requested\n")
                replyJSON = replyPublicParamJSON
                print("Sending reply = \n" + str(replyJSON) + "\n")

            elif str(data["request"]) == "User Secret Key":
                print("\n\nUser Secret Key Requested\n")
                print("Received Request =\n", data)
                

                #PARAMETER CHECK
                u_N = int_from_hex(data["N_hex"]) 
                u_e = int_from_hex(data["e_hex"])
                checkParams = (N == u_N) and (e == u_e)
                if checkParams:
                    print("User Public Parameters MATCH Server Public Parameters\n")
                    hex_publicID = data["publicID"]
                    print("Given publicID (hex format) = " + data["publicID"])
                    # print("hex_publicID is ", hex_publicID)
                    # print("    of type = ", type(hex_publicID))
                    int_publicID = int_from_hex(hex_publicID)
                    print("Given publicID (int format) = ", int_publicID)
                    int_secretKey = signRSA(N=N, exponent=d, message=int_publicID)
                    print("\nGenerated Secret Key (int format) = ", int_secretKey)
                    hex_secretKey = hex_from_int(int_secretKey)
                    print("Generated Secret Key (hex format) = ", hex_secretKey)
                    replySecretKeyJSON = {
                        "response": "User Secret Key",
                        "publicID": hex_publicID,
                        "secretKey": hex_secretKey
                    }
                    replyJSON = replySecretKeyJSON
                    print("\nSending reply = \n" + str(replyJSON) + "\n")

                else:
                    print("\n\nUser Public Parameters DO NOT MATCH Server Public Parameters")
                    print("Suggest to update parameters\n\n")
                    errorJSON = {
                        "response": "ERROR",
                        "message": "Public Parameters DO NOT MATCH"
                    }
                    replyJSON = errorJSON
                
            elif str(data["request"]) == "Blind User Verification":
                print("\n\nBlind User Verification Requested\n")
                print("Received Request =\n", data)

                # testDataJSON = data         #For testing reasons. This must be run first
                # saveStringToFile(testDataJSON, "myTestJSON.txt")

                CMT = data["CMT"]
                print("\nCMT = ", CMT)
                hex_publicID = data["publicID"]
                int_publicID = int_from_hex(hex_publicID)
                Y = int_from_hex(CMT)
                print("CMT (in int format) = Y =\n", Y)

                #PARAMETER CHECK
                u_N = int_from_hex(data["N_hex"]) 
                u_e = int_from_hex(data["e_hex"])
                checkParams = (N == u_N) and (e == u_e)
                if checkParams:
                    print("\nUser Public Parameters MATCH Server Public Parameters\n")
                    # Generate Challenge
                    c = generateCHL(N=N)
                    CHL = hex_from_int(c)
                    print("CHL to be sent = ", CHL)
                    challengeJSON = {
                        "response": "Challenge",
                        "CHL": CHL
                    }
                    print("Sending to client the challenge = \n", challengeJSON)
                    await websocket.send(json.dumps(challengeJSON))

                    unprocessed_RSP = await websocket.recv()
                    processed_RSP = json.loads(unprocessed_RSP)
                    print("\nReceiving Response from client = \n", processed_RSP)
                    RSP = processed_RSP["RSP"]
                    print("\nreceived RSP = ", RSP)
                    z = int_from_hex(RSP)
                    print("z = ", z)
                    
                    identityCheck = GQ_IBI_verification(N=u_N, e=u_e, Y=Y, c=c, z=z, intPublicID=int_publicID)
                    if identityCheck == True:
                        replyJSON = {
                            "response": "Verification Result",
                            "message": "User Verification is Successful!",
                            "identityCheck": True
                        }
                    elif identityCheck == False:
                        reply = "User Verification is Unsuccessful!"
                        replyJSON = {
                            "response": "Verification Result",
                            "message": "User Verification is Unsuccessful!",
                            "identityCheck": False
                        }
                    else:
                        replyJSON = {
                            "response": "ERROR",
                            "message": "Something is wrong with Verification in Server"
                        }


                else:
                    errorJSON = {
                        "response": "ERROR",
                        "message": "Public Parameters DO NOT MATCH"
                    }
                    replyJSON = errorJSON
                
                print("\nSending final reply to client = \n", replyJSON)
                


            elif str(data["request"]) == "requestInfo":
                print("\nPython Client is requesting information for test\n")
                print("Information to be sent = \n", testDataJSON)
                replyJSON = testDataJSON

            else:
                errorJSON = {
                    "response": "ERROR",
                    "message": "Unknown Request Received: " + str(data["request"])
                }
                replyJSON = errorJSON

            reply = json.dumps(replyJSON)
            await websocket.send(reply)
        except websockets.ConnectionClosedOK:
            print("\nWebsocket Connection Closed\n")
            break

start_server = websockets.serve(handler, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()


