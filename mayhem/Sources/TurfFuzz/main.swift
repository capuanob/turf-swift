#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import Turf

@_cdecl("LLVMFuzzerTestOneInput")
public func TurfFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)

    let choice = fdp.ConsumeIntegralInRange(from: 0, to: 2)

    do {
        switch (choice) {
        case 0:
            let d = try JSONDecoder().decode(GeoJSONObject.self, from: fdp.ConsumeRemainingData())
            try JSONEncoder().encode(d)
        case 1:
            try Point(wkt: fdp.ConsumeRemainingString())
        default:
            try Geometry(wkt: fdp.ConsumeRemainingString())
        }
    }
    catch is DecodingError {
        return -1;
    }
    catch let error {
        if error.localizedDescription.contains("Unexpected token") {
            return -1;
        }
        else if error.localizedDescription.contains("WKT") {
            return -1;
        }
        else {
            print("Error contents: " + error.localizedDescription)
            print("Error type: ")
            print(type(of: error))
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}