//
//  SecureStorageQuery.swift
//  Created by Lukas Vollenweider on 23.09.19.
//

import Foundation

struct SecureStorageQuery {
    
    let service: String
    let key: String
    let value: String?
    
    var config: Config
    
    init?(from command: CDVInvokedUrlCommand) {
        guard command.arguments.count >= 2 else {
            print("Number of arguments does not match!")
            return nil
        }
        
        guard let service = command.argument(at: 0) as? String,
            let key = command.argument(at: 1) as? String else {
            return nil
        }
        
        self.service = service
        self.key = key
        value = command.argument(at: 2) as? String
        
        config = Config()
        if let configData = command.argument(at: 3) as? [String: Any] {
            if let json = try? JSONSerialization.data(withJSONObject: configData, options: []) {
                let decoder = JSONDecoder()
                if let parsedConfig = try? decoder.decode(Config.self, from: json) {
                    self.config = parsedConfig
                }
            }
        }
    }
}

extension SecureStorageQuery {
    struct Config: Codable {
        var requiresUserPresence: Bool?
        var allowableAuthenticationReuseDuration: Int?
    }
}
