import Foundation

/**
 A JSON value represents an object, array, or fragment.
 
 This type does not represent the `null` value in JSON. Use `Optional<JSONValue>` wherever `null` is accepted.
 */
public enum JSONValue: Equatable {
    // case null would be redundant to Optional.none
    
    /// A string.
    case string(_ string: String)
    
    /**
     A floating-point number.
     
     JSON does not distinguish numeric types of different precisions. If you need integer precision, cast the value to an `Int`.
     */
    case number(_ number: Double)
    
    /// A Boolean value.
    case boolean(_ bool: Bool)
    
    /// A heterogeneous array of JSON values and `null` values.
    case array(_ values: JSONArray)
    
    /// An object containing JSON values and `null` values keyed by strings.
    case object(_ properties: JSONObject)
    
    /// Initializes a JSON value representing the given JSON value–convertible instance.
    public init(_ value: JSONValueConvertible) {
        self = value.jsonValue
    }
    
    /**
     Initializes a JSON value representing the given integer.
     
     - parameter number: An integer. JSON does not distinguish numeric types of different precisions, so the integer is stored as a floating-point number.
     */
    public init<Source>(_ number: Source) where Source: BinaryInteger {
        self.init(Double(number))
    }
    
    /// Initializes a JSON value representing the given floating-point number.
    public init<Source>(_ number: Source) where Source: BinaryFloatingPoint {
        self.init(Double(number))
    }
    
    /// Initializes a JSON value representing the given JSON-convertible array.
    public init(_ values: [JSONValueConvertible?]) {
        self = .array(JSONArray(values))
    }
    
    /// Initializes a JSON value representing the given JSON-convertible object.
    public init(_ properties: [String: JSONValueConvertible?]) {
        self = .object(JSONObject(properties))
    }
}

extension JSONValue: RawRepresentable {
    public typealias RawValue = Any
    
    public init?(rawValue: Any) {
        // Like `JSONSerialization.jsonObject(with:options:)` with `JSONSerialization.ReadingOptions.fragmentsAllowed` specified.
        if let bool = rawValue as? Bool {
            self = .boolean(bool)
        } else if let string = rawValue as? String {
            self = .string(string)
        } else if let number = rawValue as? NSNumber {
            self = .number(number.doubleValue)
        } else if let rawArray = rawValue as? JSONArray.RawValue,
                  let array = JSONArray(rawValue: rawArray) {
            self = .array(array)
        } else if let rawObject = rawValue as? JSONObject.RawValue,
                  let object = JSONObject(rawValue: rawObject) {
            self = .object(object)
        } else {
            return nil
        }
    }
    
    public var rawValue: Any {
        switch self {
        case let .boolean(value):
            return value
        case let .string(value):
            return value
        case let .number(value):
            return value
        case let .object(value):
            return value.rawValue
        case let .array(value):
            return value.rawValue
        }
    }
}

/**
 A JSON array of `JSONValue` instances.
 */
public typealias JSONArray = [JSONValue?]

extension JSONArray {
    public init(_ elements: [JSONValueConvertible?]) {
        let values = elements.map { $0?.jsonValue }
        self.init(values)
    }
}

extension JSONArray: RawRepresentable {
    public typealias RawValue = [Any?]
    
    public init?(rawValue values: RawValue) {
        self = values.map(JSONValue.init(rawValue:))
    }
    
    public var rawValue: RawValue {
        return map { $0?.rawValue }
    }
}

/**
 A JSON object represented in memory by a dictionary with strings as keys and `JSONValue` instances as values.
 */
public typealias JSONObject = [String: JSONValue?]

extension JSONObject {
    public init(_ elements: [String: JSONValueConvertible?]) {
        self.init(uniqueKeysWithValues: elements.map { ($0.0, $0.1?.jsonValue) })
    }
}

extension JSONObject: RawRepresentable {
    public typealias RawValue = [String: Any?]
    
    public init?(rawValue: RawValue) {
        self = rawValue.mapValues { $0.flatMap(JSONValue.init(rawValue:)) }
    }
    
    public var rawValue: RawValue {
        return mapValues { $0?.rawValue }
    }
}

extension JSONValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.init(value)
    }
}

extension JSONValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self.init(value)
    }
}

extension JSONValue: ExpressibleByFloatLiteral {
    public init(floatLiteral value: FloatLiteralType) {
        self.init(value)
    }
}

extension JSONValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: BooleanLiteralType) {
        self.init(value)
    }
}

extension JSONValue: ExpressibleByArrayLiteral {
    public typealias ArrayLiteralElement = JSONValueConvertible?
    
    public init(arrayLiteral elements: ArrayLiteralElement...) {
        self.init(elements)
    }
}

extension JSONValue: ExpressibleByDictionaryLiteral {
    public typealias Key = String
    public typealias Value = JSONValueConvertible?
    
    public init(dictionaryLiteral elements: (Key, Value)...) {
        self = .object(JSONObject(uniqueKeysWithValues: elements.map { ($0.0, $0.1?.jsonValue) }))
    }
}

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let boolean = try? container.decode(Bool.self) {
            self = .boolean(boolean)
        } else if let number = try? container.decode(Double.self) {
            self = .number(number)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let object = try? container.decode(JSONObject.self) {
            self = .object(object)
        } else if let array = try? container.decode(JSONArray.self) {
            self = .array(array)
        } else {
            throw DecodingError.typeMismatch(JSONValue.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Unable to decode as a JSONValue."))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .boolean(value):
            try container.encode(value)
        case let .string(value):
            try container.encode(value)
        case let .number(value):
            try container.encode(value)
        case let .object(value):
            try container.encode(value)
        case let .array(value):
            try container.encode(value)
        }
    }
}

/**
 A type that can be represented as a `JSONValue` instance.
 */
public protocol JSONValueConvertible {
    /// The instance wrapped in a `JSONValue` instance.
    var jsonValue: JSONValue { get }
}

extension String: JSONValueConvertible {
    public var jsonValue: JSONValue { return .string(self) }
}

extension Int: JSONValueConvertible {
    public var jsonValue: JSONValue { return .number(Double(self)) }
}

extension Double: JSONValueConvertible {
    public var jsonValue: JSONValue { return .number(Double(self)) }
}

extension Bool: JSONValueConvertible {
    public var jsonValue: JSONValue { return .boolean(self) }
}

extension Array: JSONValueConvertible where Element == JSONValueConvertible? {
    public var jsonValue: JSONValue {
        return .array(map { $0?.jsonValue })
    }
}

extension Dictionary: JSONValueConvertible where Key == String, Value == JSONValueConvertible? {
    public var jsonValue: JSONValue {
        return .object(JSONObject(uniqueKeysWithValues: map { ($0.0, $0.1?.jsonValue) }))
    }
}
