DROP TABLE IF EXISTS SameNetwork;
DROP TABLE IF EXISTS History;
DROP TABLE IF EXISTS ExtHosts;
DROP TABLE IF EXISTS IntHosts;

CREATE TABLE SameNetwork (
    IpAddress VARCHAR(15) PRIMARY KEY,
    NetworkStatus BIT NOT NULL
);

CREATE TABLE ExtHosts (
    IpAddress VARCHAR(15) PRIMARY KEY,
    SSLOrgName VARCHAR(30) NULL,
    DNSName VARCHAR(30) NULL,
    HTTPHeader VARCHAR(30) NULL,
    FOREIGN KEY(IpAddress) REFERENCES SameNetwork(IpAddress)
);

CREATE TABLE IntHosts (
    IpAddress VARCHAR(15) PRIMARY KEY,
    MacAddress VARCHAR(17) NULL,
    DeviceManufacturer VARCHAR(30) NULL,
    FOREIGN KEY(IpAddress) REFERENCES SameNetwork(IpAddress)
);

CREATE TABLE History (
    Time DATETIME2 NOT NULL,
    Source VARCHAR(15) NOT NULL,
    Destination VARCHAR(15) NOT NULL,
    Kilobytes REAL,
    FOREIGN KEY (Source) REFERENCES SameNetwork(IpAddress),
    FOREIGN KEY (Destination) REFERENCES SameNetwork(IpAddress),
    PRIMARY KEY (Time, Source, Destination)
);
