/* eslint-disable @typescript-eslint/naming-convention */
import { sha3_256 } from 'js-sha3'
import { Helper } from './utils/helper'
import { Versions } from './utils/enums'

import Sodium from 'libsodium-wrappers'

/**
 * @description ViperAAT implementation
 * (version 0.0.1 of the specification:
 */
export class ViperAAT {
  /**
   *
   * @description Instantiate the ViperAAT class, automatically creates the signature using the provided parameters
   * 
   * @param {string} version - Version information.
   * @param {string} clientPublicKey - Client Public Key.
   * @param {string} applicationPublicKey - Application Public Key.
   * @param {string} privateKey - Private Key.
   * @returns {ViperAAT} - Viper Authentication Token object.
   * @memberof ViperAAT
   */
  public static from(
    version: string,
    clientPublicKey: string,
    applicationPublicKey: string,
    privateKey: string,
  ): Promise<ViperAAT> {
    return Sodium.ready.then(() => {
      if (Versions.isSupported(version)) {
        const applicationSignature = this.sign(
          {
            version: version,
            app_pub_key: applicationPublicKey,
            client_pub_key: clientPublicKey,
            signature: '',
          },
          privateKey,
        )
        return new ViperAAT(version, clientPublicKey, applicationPublicKey, applicationSignature)
      } else {
        console.log("VIPER AAT ERROR")
        throw new TypeError('Provided version is not supported.')
      }
    })
  }

  /**
   *
   * @description Instantiate the ViperAAT class using an already generated signature
   * 
   * @param {string} version - Version information.
   * @param {string} clientPublicKey - Client Public Key.
   * @param {string} applicationPublicKey - Application Public Key.
   * @param {string} signature - Signature.
   * @returns {ViperAAT} - Viper Authentication Token object.
   * @memberof ViperAAT
   */
  public static fromSignature(
    version: string,
    clientPublicKey: string,
    applicationPublicKey: string,
    signature: string,
  ): Promise<ViperAAT> {
    return Sodium.ready.then(() => {
      if (Versions.isSupported(version)) {

        const payload = {
          version: version,
          app_pub_key: applicationPublicKey,
          client_pub_key: clientPublicKey,
          signature: ''
        }


        const hash = sha3_256.create()
        hash.update(JSON.stringify(payload))
        const bufferPayload = Helper.fromHex(hash.hex())
        const bufferApplicationSignature = Helper.fromHex(signature)
        const bufferApplicationPublicKey = Helper.fromHex(applicationPublicKey)
        const isValid = Sodium.crypto_sign_verify_detached(bufferApplicationSignature, bufferPayload, bufferApplicationPublicKey)

        if (!isValid) {
          throw new TypeError('Invalid AAT Signature.')
        }

        return new ViperAAT(version, clientPublicKey, applicationPublicKey, signature)
      } else {
        console.log("VIPER AAT ERROR")
        throw new TypeError('Provided version is not supported.')
      }
    })
  }

  /**
   * @description Given an aatPayload object, create a SHA3 hash of it and signs it using privateKey.
   * 
   * @param aatPayload - Object with the mandatory parameters.
   * @param privateKey - Private Key
   */
  private static sign(aatPayload: object, privateKey: string): string {
    // Generate sha3 hash of the aat payload object
    const hash = sha3_256.create()
    hash.update(JSON.stringify(aatPayload))
    const bufferPayload = Helper.fromHex(hash.hex())

    if (Helper.byteLength(privateKey) === 64 && Helper.validateHexStr(privateKey)) {
      // Return signed aat payload hash
      const privateKeyBuffer = Helper.fromHex(privateKey)
      const signature = Sodium.crypto_sign(bufferPayload, privateKeyBuffer, 'hex')

      return signature.substring(0, 128)
    } else {
      throw new TypeError("Private key can't be an empty string")
    }
  }

  public readonly version: string = Versions['0.0.1'].toString()
  public readonly clientPublicKey: string
  public readonly applicationPublicKey: string
  public readonly applicationSignature: string

  /**
   * @description ViperAAT constructor
   * 
   * @param {string} version - Version information.
   * @param {string} clientPublicKey - Client Public Key.
   * @param {string} applicationPublicKey - Application Public Key.
   * @param {string} applicationSignature - Application Signature.
   */
  constructor(
    version: string, 
    clientPublicKey: string, 
    applicationPublicKey: string, 
    applicationSignature: string
  ) {
    this.version = version
    this.clientPublicKey = clientPublicKey
    this.applicationPublicKey = applicationPublicKey
    this.applicationSignature = applicationSignature

    if (!this.isValid()) {
      throw new TypeError('Invalid properties format.')
    }
  }

  /**
   * @description Returns whether or not this is a valid AAT according to the current version.
   * 
   */
  public isValid(): boolean {
    return (
      this.version.length !== 0 &&
      Helper.byteLength(this.clientPublicKey) === 32 &&
      Helper.validateHexStr(this.clientPublicKey) &&
      Helper.byteLength(this.applicationPublicKey) === 32 &&
      Helper.validateHexStr(this.applicationPublicKey) &&
      Helper.validateHexStr(this.applicationSignature)
    )
  }
}
