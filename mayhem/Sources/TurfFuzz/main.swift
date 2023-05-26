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

    let choice = fdp.ConsumeIntegralInRange(from: 0, to: 5)

    do {
        switch (choice) {
        case 0:
            let d = try JSONDecoder().decode(GeoJSONObject.self, from: fdp.ConsumeRemainingData())
            try JSONEncoder().encode(d)
        case 1:
            try Point(wkt: fdp.ConsumeRemainingString())
        case 2:
            let ld = LocationDistance(signOf: fdp.ConsumeDouble(), magnitudeOf: fdp.ConsumeDouble())
            let ls = try LineString(wkt: fdp.ConsumeRandomLengthString())
            ls.coordinateFromStart(distance: ld)
        case 3:
            let ld = LocationDistance(signOf: fdp.ConsumeDouble(), magnitudeOf: fdp.ConsumeDouble())
            let lit_one: UInt64 = fdp.ConsumeIntegral()
            let lit_two: UInt64 = fdp.ConsumeIntegral()

            let int_max = UInt64(Int64.max)
            if lit_one <= int_max && lit_two <= int_max {
                let coord = LocationCoordinate2D(latitude: LocationDegrees(integerLiteral: Int64(lit_one)),
                        longitude: LocationDegrees(integerLiteral: Int64(lit_two)))
                let p = Polygon(center: coord, radius: ld, vertices: fdp.ConsumeIntegralInRange(from: 0, to: 100))
            }
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