const std = @import("std");
const sqlite = @import("sqlite");

pub var data_dir: []const u8 = "";

pub fn handler(allocator: std.mem.Allocator, account_id: []const u8, event_data: []const u8) ![]const u8 {
    _ = event_data;
    // Request:
    //
    // {
    // "AttributeDefinitions": [{"AttributeName": "Artist", "AttributeType": "S"}, {"AttributeName": "SongTitle", "AttributeType": "S"}],
    // "TableName": "dm",
    // "KeySchema": [
    //      {"AttributeName": "Artist", "KeyType": "HASH"},
    //      {"AttributeName": "SongTitle", "KeyType": "RANGE"}
    // ],
    // "ProvisionedThroughput":
    //   {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    // "Tags": [{"Key": "Owner", "Value": "blueTeam"}]
    // }
    //
    // Server side Input validation error on live DDB results in this for a 2 char table name
    // 400 - bad request
    // {"__type":"com.amazon.coral.validate#ValidationException","message":"TableName must be at least 3 characters long and at most 255 characters long"}
    // TODO: We'll need hold of the server response object here so we can muck with status
    // for client validation issues such as "table names must be > 2"

    // TODO: If the file exists, this will blow up
    // TODO: Need configuration for what directory to use
    // TODO: File names should align to account ids
    // TODO: Should this be a pool, and if so, how would we know when to close?
    const file_without_path = try std.fmt.allocPrint(allocator, "ddb-{s}.db", .{account_id});
    defer allocator.free(file_without_path);
    const db_file_name = try std.fs.path.join(allocator, &[_][]const u8{ data_dir, file_without_path });
    defer allocator.free(db_file_name);
    const mode = if (@import("builtin").is_test) sqlite.Db.Mode.Memory else sqlite.Db.Mode{ .File = "donotuse.db" };
    const exists = std.fs.cwd().statFile(file_without_path) catch null;
    var db = try sqlite.Db.init(.{
        .mode = mode,
        .open_flags = .{
            .write = true,
            .create = exists == null,
        },
        .threading_mode = .MultiThread,
    });

    // TODO: Create metadata table by account on first create
    // DDB minimum table name length is 3. DDB local creates this table with metadata
    // This of course is only if the database is first run
    // try db.exec(
    //     \\CREATE TABLE dm (
    //     \\    TableName TEXT,
    //     \\    CreationDateTime INTEGER,
    //     \\    LastDecreaseDate INTEGER,
    //     \\    LastIncreaseDate INTEGER,
    //     \\    NumberOfDecreasesToday INTEGER,
    //     \\    ReadCapacityUnits INTEGER,
    //     \\    WriteCapacityUnits INTEGER,
    //     \\    TableInfo BLOB,
    //     \\    BillingMode INTEGER DEFAULT 0,
    //     \\    PayPerRequestDateTime INTEGER DEFAULT 0,
    //     \\    PRIMARY KEY(TableName)
    // );
    //
    // Tableinfo for Music collection example becomes:
    //
    // {"Attributes":[{"AttributeName":"Artist","AttributeType":"S"},{"AttributeName":"SongTitle","AttributeType":"S"}],"GSIList":[],"GSIDescList":[],"SQLiteIndex":{"":[{"DynamoDBAttribute":{"AttributeName":"Artist","AttributeType":"S"},"KeyType":"HASH","SQLiteColumnName":"hashKey","SQLiteDataType":"TEXT"},{"DynamoDBAttribute":{"AttributeName":"SongTitle","AttributeType":"S"},"KeyType":"RANGE","SQLiteColumnName":"rangeKey","SQLiteDataType":"TEXT"}]},"UniqueIndexes":[{"DynamoDBAttribute":{"AttributeName":"Artist","AttributeType":"S"},"KeyType":"HASH","SQLiteColumnName":"hashKey","SQLiteDataType":"TEXT"},{"DynamoDBAttribute":{"AttributeName":"SongTitle","AttributeType":"S"},"KeyType":"RANGE","SQLiteColumnName":"rangeKey","SQLiteDataType":"TEXT"}],"UniqueGSIIndexes":[]}
    try db.exec("CREATE TABLE user(id integer primary key, age integer, name text)", .{}, .{});
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();
    try writer.print("table created for account {s}\n", .{account_id});
    return al.toOwnedSlice();

    // This is what the music collection sample creates
    // CREATE TABLE IF NOT EXISTS "MusicCollection" (hashKey TEXT DEFAULT NULL, rangeKey TEXT DEFAULT NULL, hashValue BLOB NOT NULL, rangeValue BLOB NOT NULL, itemSize INTEGER DEFAULT 0, ObjectJSON BLOB NOT NULL, PRIMARY KEY(hashKey, rangeKey));
    // CREATE INDEX "MusicCollection*HVI" ON "MusicCollection" (hashValue);
}

test "can create a table" {
    const allocator = std.testing.allocator;
    const request =
        \\ {
        \\ "AttributeDefinitions":
        \\    [
        \\     {"AttributeName": "Artist", "AttributeType": "S"},
        \\     {"AttributeName": "SongTitle", "AttributeType": "S"}
        \\    ],
        \\ "TableName": "dm",
        \\ "KeySchema": [
        \\      {"AttributeName": "Artist", "KeyType": "HASH"},
        \\      {"AttributeName": "SongTitle", "KeyType": "RANGE"}
        \\ ],
        \\ "ProvisionedThroughput":
        \\   {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        \\ "Tags": [{"Key": "Owner", "Value": "blueTeam"}]
        \\ }
    ;
    const output = try handler(allocator, "1234", request);
    defer allocator.free(output);
    // TODO: test output
}
