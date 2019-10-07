//
//  SecureStorage.swift
//  Created by Lukas Vollenweider on 23.09.19.
//

import Foundation
import Security
import LocalAuthentication

@objc(SecureStorage) class SecureStorage: CDVPlugin {
    //MARK: - JavaScript Interface
    
    @objc(init:)
    func initialize(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK,
                                           messageAs: "The plugin succeeded")
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
        send(status: CDVCommandStatus_OK,
             description: nil,
             callbackId: command.callbackId)
    }
    
    @objc(set:)
    func storeItem(command: CDVInvokedUrlCommand) {
        guard let storageQuery = SecureStorageQuery(from: command),
            let value = storageQuery.value else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not parse query!",
                 callbackId: command.callbackId)
            return
        }
                
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: storageQuery.service,
            kSecAttrAccount as String: storageQuery.key,
            kSecValueData as String: value.data(using: String.Encoding.utf8)!
        ]
        
        if let requiresUserPresence = storageQuery.config.requiresUserPresence, requiresUserPresence {
            var error: Unmanaged<CFError>?
            
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .userPresence,
                &error
            )
            
            guard error == nil else {
                send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                    description: "Could not create access control flag due to: \(error!.takeRetainedValue().localizedDescription)",
                    callbackId: command.callbackId)
                
                return
            }
            
            let context = LAContext()
            context.touchIDAuthenticationAllowableReuseDuration = TimeInterval(storageQuery.config.allowableAuthenticationReuseDuration ?? 0)
            
            query[kSecAttrAccessControl as String] = access
            query[kSecUseAuthenticationContext as String] = context
        }

                
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            if status == errSecDuplicateItem {
                updateExistingItem(queryConfig: storageQuery, command: command)
                return
            }
            
            let error = KeychainError(status: status)
            send(status: CDVCommandStatus_ERROR,
                 description: "Could not store item: \(error.localizedDescription)",
                callbackId: command.callbackId)
            return
        }
        
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK,
                                           messageAs: storageQuery.key)
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }
    
    @objc(get:)
    func fetchItem(command: CDVInvokedUrlCommand) {
        guard let queryConfig = SecureStorageQuery(from: command) else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not parse query!",
                 callbackId: command.callbackId)
            
            return
        }
        
        let (item, status) = queryKeychainForItem(queryConfig: queryConfig)
        
        guard item != nil, status == errSecSuccess else {
            let error = KeychainError(status: status)
            
            send(status: CDVCommandStatus_ERROR,
                               description: "Could not fetch item: \(error.localizedDescription)",
                               callbackId: command.callbackId)
            return
        }
        
        guard let existingItem = item as? [String: Any],
            let data = existingItem[kSecValueData as String] as? Data,
            let value = String(data: data, encoding: String.Encoding.utf8) else {
                let error = KeychainError(status: status)
                
                send(status: CDVCommandStatus_ERROR,
                    description: "Could not parse returning item: \(error.localizedDescription)",
                    callbackId: command.callbackId)

                return
        }
        
        send(status: CDVCommandStatus_OK, description: value, callbackId: command.callbackId)
    }
    
    @objc(keys:)
    func getKeys(command: CDVInvokedUrlCommand) {
        guard let service = command.argument(at: 0) as? String else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not parse server!",
                 callbackId: command.callbackId)
            return
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            let error = KeychainError(status: status)
            
            send(status: CDVCommandStatus_ERROR,
                               description: "Could not fetch item: \(error.localizedDescription)",
                               callbackId: command.callbackId)
            return
        }

        guard let items = item as? [[String: Any]] else {
            let error = KeychainError(status: status)
            
            send(status: CDVCommandStatus_ERROR,
                description: "Could not parse returning item: \(error.localizedDescription)",
                callbackId: command.callbackId)

            return
        }

        let keys = items.compactMap({ $0[kSecAttrAccount as String] as? String })
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: keys)
        self.commandDelegate!.send(pluginResult, callbackId: command.callbackId)
    }
    
    @objc(remove:)
    func removeItem(command: CDVInvokedUrlCommand) {
        guard let queryConfig = SecureStorageQuery(from: command) else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not parse query!",
                 callbackId: command.callbackId)
            
            return
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: queryConfig.service,
            kSecAttrAccount as String: queryConfig.key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            let error = KeychainError(status: status)

            send(status: CDVCommandStatus_ERROR,
                description: "Could not delete keys: \(error.localizedDescription)",
                callbackId: command.callbackId)
            
            return
        }
        
        send(status: CDVCommandStatus_OK,
             description: queryConfig.key,
             callbackId: command.callbackId)
    }
    
    @objc(clear:)
    func deleteAllItems(command: CDVInvokedUrlCommand) {
        guard let service = command.argument(at: 0) as? String else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not parse server!",
                 callbackId: command.callbackId)
            return
        }
        
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            let error = KeychainError(status: status)

            send(status: CDVCommandStatus_ERROR,
                description: "Could not delete keys: \(error.localizedDescription)",
                callbackId: command.callbackId)
            
            return
        }
        
        send(status: CDVCommandStatus_OK,
             description: "Keychain successfully cleared for server: \(service)",
             callbackId: command.callbackId)
    }
    
    //MARK: - Helpers
    private func send(status: CDVCommandStatus, description: String?, callbackId: String) {
        let pluginResult: CDVPluginResult
        if let description = description {
            pluginResult = CDVPluginResult(status: status, messageAs: description)
        } else {
            pluginResult = CDVPluginResult(status: status)
        }
        self.commandDelegate!.send(pluginResult, callbackId: callbackId)
    }
    
    private func queryKeychainForItem(queryConfig: SecureStorageQuery) -> (CFTypeRef?, OSStatus) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: queryConfig.service,
            kSecAttrAccount as String: queryConfig.key,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return (nil, status)
        }
        
        return (item, status)
    }
    
    private func updateExistingItem(queryConfig: SecureStorageQuery, command: CDVInvokedUrlCommand) {
        guard let value = queryConfig.value else {
            send(status: CDVCommandStatus_INSTANTIATION_EXCEPTION,
                 description: "Could not update existing item with empty value!",
                 callbackId: command.callbackId)
            return
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: queryConfig.service,
            kSecAttrAccount as String: queryConfig.key
        ]
        
        let attributes: [String: Any] = [
            kSecValueData as String: value.data(using: String.Encoding.utf8)!
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecSuccess else {
            let error = KeychainError(status: status)
            send(status: CDVCommandStatus_ERROR,
                description: "Could not update existing item: \(error.localizedDescription)",
                callbackId: command.callbackId)
            return
        }
        
        send(status: CDVCommandStatus_OK,
             description: queryConfig.key,
             callbackId: command.callbackId)
    }
}

extension SecureStorage {
    struct KeychainError: Error {
        var status: OSStatus

        var localizedDescription: String {
            if #available(iOS 11.3, *) {
                return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error."
            } else {
                return "Unknown error: \(status.description)"
            }
        }
    }
}
