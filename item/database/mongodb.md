# MongoDB 기본 명령어 정리

## 1. 접속 및 기본 설정

```bash
# MongoDB 접속
mongo
mongosh  # MongoDB 6.0+ 새로운 셸

# 원격 접속
mongo mongodb://hostname:27017/database
mongosh "mongodb://hostname:27017/database"

# 인증 접속
mongo mongodb://username:password@hostname:27017/database
mongosh "mongodb://username:password@hostname:27017/database"

# SSL 접속
mongosh "mongodb://hostname:27017/database?ssl=true"

# 레플리카셋 접속
mongosh "mongodb://host1:27017,host2:27017,host3:27017/database?replicaSet=myReplicaSet"

# 로컬 접속 (기본 포트)
mongo localhost:27017
mongosh mongodb://localhost:27017

# 특정 데이터베이스로 직접 접속
mongo myDatabase
mongosh myDatabase
```

## 2. MongoDB 셸 기본 명령어

```javascript
// 도움말
help
db.help()
db.collection.help()

// 현재 데이터베이스 확인
db
db.getName()

// 데이터베이스 목록
show dbs
show databases

// 데이터베이스 전환/생성
use myDatabase

// 컬렉션 목록
show collections
show tables

// 현재 데이터베이스 삭제
db.dropDatabase()

// 종료
exit
quit()
```

## 3. 데이터베이스 관리

```javascript
// 데이터베이스 생성 (사용 시 자동 생성)
use newDatabase

// 데이터베이스 정보
db.stats()
db.serverStatus()

// 데이터베이스 크기
db.stats().dataSize
db.stats().storageSize

// 현재 연결 정보
db.adminCommand("connectionStatus")

// 서버 버전
db.version()
db.serverBuildInfo()

// 관리자 명령어
db.adminCommand("listDatabases")
db.adminCommand("serverStatus")
```

## 4. 컬렉션 관리

```javascript
// 컬렉션 생성 (명시적)
db.createCollection("users");
db.createCollection("users", { capped: true, size: 100000, max: 100 });

// 컬렉션 생성 (암시적 - 첫 문서 삽입 시)
db.users.insertOne({ name: "John", age: 30 });

// 컬렉션 정보
db.users.stats();

// 컬렉션 이름 변경
db.users.renameCollection("customers");

// 컬렉션 삭제
db.users.drop();

// 컬렉션 존재 확인
db.getCollectionNames().indexOf("users") !== -1;
```

## 5. 문서 삽입 (Create)

```javascript
// 단일 문서 삽입
db.users.insertOne({
  name: "John Doe",
  email: "john@example.com",
  age: 30,
  city: "Seoul",
  hobbies: ["reading", "swimming"],
  createdAt: new Date(),
});

// 다중 문서 삽입
db.users.insertMany([
  { name: "Alice", email: "alice@example.com", age: 25 },
  { name: "Bob", email: "bob@example.com", age: 35 },
  { name: "Charlie", email: "charlie@example.com", age: 28 },
]);

// _id 지정하여 삽입
db.users.insertOne({
  _id: ObjectId("507f1f77bcf86cd799439011"),
  name: "Custom ID User",
  email: "custom@example.com",
});

// 삽입 결과 확인
var result = db.users.insertOne({ name: "Test", email: "test@example.com" });
print(result.insertedId);

// 대량 삽입 최적화
db.users.insertMany(documents, { ordered: false }); // 순서 무관, 병렬 처리
```

## 6. 문서 조회 (Read)

```javascript
// 모든 문서 조회
db.users.find();
db.users.find().pretty();

// 조건부 조회
db.users.find({ name: "John Doe" });
db.users.find({ age: 30 });
db.users.find({ age: { $gt: 25 } }); // age > 25
db.users.find({ age: { $gte: 25, $lt: 40 } }); // 25 <= age < 40

// 단일 문서 조회
db.users.findOne({ name: "John Doe" });
db.users.findOne({}, { sort: { age: -1 } }); // 가장 나이 많은 사용자

// 필드 선택 (프로젝션)
db.users.find({}, { name: 1, email: 1 }); // name, email만
db.users.find({}, { age: 0 }); // age 제외하고 모든 필드
db.users.find({}, { _id: 0, name: 1, email: 1 }); // _id 제외

// 배열 필드 조회
db.users.find({ hobbies: "reading" }); // 배열에 "reading" 포함
db.users.find({ hobbies: { $in: ["reading", "swimming"] } });
db.users.find({ hobbies: { $all: ["reading", "swimming"] } }); // 모두 포함
db.users.find({ "hobbies.0": "reading" }); // 첫 번째 요소가 "reading"

// 정규식 검색
db.users.find({ name: /john/i }); // 대소문자 무관하게 "john" 포함
db.users.find({ email: /^john/ }); // "john"으로 시작

// 중첩 객체 조회
db.users.find({ "address.city": "Seoul" });

// 존재 여부 확인
db.users.find({ phone: { $exists: true } });
db.users.find({ phone: { $exists: false } });

// 정렬
db.users.find().sort({ age: 1 }); // 오름차순
db.users.find().sort({ age: -1, name: 1 }); // age 내림차순, name 오름차순

// 제한 및 건너뛰기
db.users.find().limit(10);
db.users.find().skip(20).limit(10); // 페이징

// 개수 세기
db.users.countDocuments();
db.users.countDocuments({ age: { $gt: 25 } });
db.users.estimatedDocumentCount(); // 빠른 근사치
```

## 7. 문서 수정 (Update)

```javascript
// 단일 문서 수정
db.users.updateOne({ name: "John Doe" }, { $set: { age: 31, city: "Busan" } });

// 다중 문서 수정
db.users.updateMany({ city: "Seoul" }, { $set: { country: "Korea" } });

// 필드 추가/제거
db.users.updateOne(
  { name: "John Doe" },
  {
    $set: { phone: "010-1234-5678" },
    $unset: { oldField: "" },
  }
);

// 배열 수정
db.users.updateOne(
  { name: "John Doe" },
  { $push: { hobbies: "cooking" } } // 배열에 추가
);

db.users.updateOne(
  { name: "John Doe" },
  { $pull: { hobbies: "swimming" } } // 배열에서 제거
);

db.users.updateOne(
  { name: "John Doe" },
  { $addToSet: { hobbies: "reading" } } // 중복 없이 추가
);

// 숫자 증감
db.users.updateOne(
  { name: "John Doe" },
  { $inc: { age: 1, loginCount: 1 } } // age +1, loginCount +1
);

// 조건부 수정 (upsert)
db.users.updateOne(
  { email: "new@example.com" },
  { $set: { name: "New User", age: 25 } },
  { upsert: true } // 없으면 새로 생성
);

// 여러 배열 요소 수정
db.users.updateMany(
  { "scores.subject": "math" },
  { $inc: { "scores.$.score": 5 } } // 매치된 배열 요소의 score +5
);

// 현재 날짜로 설정
db.users.updateOne(
  { name: "John Doe" },
  { $currentDate: { lastModified: true } }
);
```

## 8. 문서 삭제 (Delete)

```javascript
// 단일 문서 삭제
db.users.deleteOne({ name: "John Doe" });

// 다중 문서 삭제
db.users.deleteMany({ age: { $lt: 18 } });

// 모든 문서 삭제 (컬렉션 유지)
db.users.deleteMany({});

// 조건부 삭제
db.users.deleteMany({
  $and: [{ age: { $gt: 65 } }, { lastLogin: { $lt: new Date("2022-01-01") } }],
});

// 삭제 결과 확인
var result = db.users.deleteMany({ city: "Busan" });
print("삭제된 문서 수: " + result.deletedCount);
```

## 9. 고급 쿼리 연산자

```javascript
// 비교 연산자
db.users.find({ age: { $eq: 30 } }); // 같음
db.users.find({ age: { $ne: 30 } }); // 같지 않음
db.users.find({ age: { $gt: 30 } }); // 큼
db.users.find({ age: { $gte: 30 } }); // 크거나 같음
db.users.find({ age: { $lt: 30 } }); // 작음
db.users.find({ age: { $lte: 30 } }); // 작거나 같음
db.users.find({ age: { $in: [25, 30, 35] } }); // 포함
db.users.find({ age: { $nin: [25, 30, 35] } }); // 포함되지 않음

// 논리 연산자
db.users.find({
  $and: [{ age: { $gte: 25 } }, { age: { $lt: 40 } }],
});

db.users.find({
  $or: [{ city: "Seoul" }, { city: "Busan" }],
});

db.users.find({
  $nor: [{ age: { $lt: 18 } }, { age: { $gt: 65 } }],
});

db.users.find({ age: { $not: { $gt: 30 } } });

// 요소 연산자
db.users.find({ phone: { $exists: true } });
db.users.find({ hobbies: { $type: "array" } });
db.users.find({ age: { $type: "number" } });

// 평가 연산자
db.users.find({
  $expr: { $gt: ["$age", "$retirementAge"] },
});

db.users.find({
  $where: "this.age > 30",
});

// 텍스트 검색 (인덱스 필요)
db.articles.createIndex({ title: "text", content: "text" });
db.articles.find({ $text: { $search: "mongodb tutorial" } });
```

## 10. 집계 파이프라인 (Aggregation)

```javascript
// 기본 집계
db.users.aggregate([
  { $match: { age: { $gte: 25 } } },
  {
    $group: {
      _id: "$city",
      count: { $sum: 1 },
      avgAge: { $avg: "$age" },
    },
  },
  { $sort: { count: -1 } },
]);

// 단계별 파이프라인
db.orders.aggregate([
  // 1단계: 필터링
  { $match: { status: "completed" } },

  // 2단계: 조인 (lookup)
  {
    $lookup: {
      from: "products",
      localField: "productId",
      foreignField: "_id",
      as: "productInfo",
    },
  },

  // 3단계: 배열 언와인딩
  { $unwind: "$productInfo" },

  // 4단계: 프로젝션
  {
    $project: {
      orderId: 1,
      customerName: 1,
      productName: "$productInfo.name",
      totalAmount: { $multiply: ["$quantity", "$productInfo.price"] },
    },
  },

  // 5단계: 그룹화
  {
    $group: {
      _id: "$customerName",
      totalOrders: { $sum: 1 },
      totalSpent: { $sum: "$totalAmount" },
    },
  },

  // 6단계: 정렬
  { $sort: { totalSpent: -1 } },

  // 7단계: 제한
  { $limit: 10 },
]);

// 날짜 집계
db.sales.aggregate([
  {
    $group: {
      _id: {
        year: { $year: "$date" },
        month: { $month: "$date" },
      },
      totalSales: { $sum: "$amount" },
      avgSales: { $avg: "$amount" },
      count: { $sum: 1 },
    },
  },
  { $sort: { "_id.year": 1, "_id.month": 1 } },
]);

// 조건부 집계
db.students.aggregate([
  {
    $project: {
      name: 1,
      grade: {
        $cond: {
          if: { $gte: ["$score", 90] },
          then: "A",
          else: {
            $cond: {
              if: { $gte: ["$score", 80] },
              then: "B",
              else: "C",
            },
          },
        },
      },
    },
  },
]);

// 배열 집계
db.blogs.aggregate([
  { $unwind: "$tags" },
  {
    $group: {
      _id: "$tags",
      count: { $sum: 1 },
    },
  },
  { $sort: { count: -1 } },
]);
```

## 11. 인덱스 관리

```javascript
// 인덱스 생성
db.users.createIndex({ name: 1 }); // 오름차순
db.users.createIndex({ age: -1 }); // 내림차순
db.users.createIndex({ name: 1, age: -1 }); // 복합 인덱스

// 고유 인덱스
db.users.createIndex({ email: 1 }, { unique: true });

// 부분 인덱스
db.users.createIndex(
  { age: 1 },
  { partialFilterExpression: { age: { $exists: true } } }
);

// TTL 인덱스 (만료 시간)
db.sessions.createIndex(
  { createdAt: 1 },
  { expireAfterSeconds: 3600 } // 1시간 후 문서 자동 삭제
);

// 텍스트 인덱스
db.articles.createIndex(
  {
    title: "text",
    content: "text",
  },
  {
    weights: { title: 10, content: 1 },
    name: "article_text_index",
  }
);

// 2dsphere 인덱스 (지리적 데이터)
db.places.createIndex({ location: "2dsphere" });

// 인덱스 확인
db.users.getIndexes();
db.users.totalIndexSize();

// 인덱스 사용 통계
db.users.aggregate([{ $indexStats: {} }]);

// 인덱스 삭제
db.users.dropIndex({ name: 1 });
db.users.dropIndex("name_1");
db.users.dropIndexes(); // 모든 인덱스 삭제 (_id 제외)

// 인덱스 성능 분석
db.users.find({ name: "John" }).explain("executionStats");
```

## 12. 배열 및 중첩 문서 처리

```javascript
// 배열 쿼리
db.posts.find({ tags: "mongodb" }); // 배열에 "mongodb" 포함
db.posts.find({ tags: { $all: ["mongodb", "database"] } }); // 모든 태그 포함
db.posts.find({ tags: { $size: 3 } }); // 배열 크기가 3

// 배열 요소 위치 기반 쿼리
db.posts.find({ "comments.0.author": "John" }); // 첫 번째 댓글 작성자가 John
db.posts.find({ "scores.2": { $gt: 80 } }); // 세 번째 점수가 80 초과

// 배열 요소별 조건
db.posts.find({
  comments: {
    $elemMatch: {
      author: "John",
      rating: { $gte: 4 },
    },
  },
});

// 중첩 문서 쿼리
db.users.find({ "address.city": "Seoul" });
db.users.find({ "profile.preferences.theme": "dark" });

// 배열의 중첩 문서
db.orders.find({
  "items.product": "laptop",
  "items.quantity": { $gt: 1 },
});

// 배열 길이로 필터링
db.posts.find({
  tags: { $exists: true },
  $expr: { $gt: [{ $size: "$tags" }, 2] },
});
```

## 13. 지리적 데이터 쿼리

```javascript
// 2dsphere 인덱스 생성
db.places.createIndex({ location: "2dsphere" });

// 지점 생성
db.places.insertOne({
  name: "Seoul Tower",
  location: {
    type: "Point",
    coordinates: [126.988, 37.5502], // [경도, 위도]
  },
});

// 근처 검색
db.places.find({
  location: {
    $near: {
      $geometry: {
        type: "Point",
        coordinates: [126.978, 37.5665],
      },
      $maxDistance: 1000, // 미터
    },
  },
});

// 영역 내 검색
db.places.find({
  location: {
    $geoWithin: {
      $geometry: {
        type: "Polygon",
        coordinates: [
          [
            [126.9, 37.5],
            [127.1, 37.5],
            [127.1, 37.6],
            [126.9, 37.6],
            [126.9, 37.5],
          ],
        ],
      },
    },
  },
});

// 교차 검색
db.places.find({
  location: {
    $geoIntersects: {
      $geometry: {
        type: "LineString",
        coordinates: [
          [126.9, 37.5],
          [127.1, 37.6],
        ],
      },
    },
  },
});
```

## 14. 사용자 및 권한 관리

```javascript
// 데이터베이스 사용자 생성
use admin
db.createUser({
    user: "myUser",
    pwd: "myPassword",
    roles: [
        {role: "readWrite", db: "myDatabase"},
        {role: "read", db: "logDatabase"}
    ]
})

// 사용자 목록
db.getUsers()

// 사용자 권한 변경
db.grantRolesToUser("myUser", [
    {role: "dbAdmin", db: "myDatabase"}
])

// 사용자 삭제
db.dropUser("myUser")

// 현재 사용자 정보
db.runCommand({connectionStatus: 1})

// 역할 생성
db.createRole({
    role: "customRole",
    privileges: [
        {
            resource: {db: "myDatabase", collection: "users"},
            actions: ["find", "insert", "update"]
        }
    ],
    roles: []
})

// 인증 활성화 확인
db.adminCommand({getParameter: 1, authenticationMechanisms: 1})
```

## 15. 레플리카셋 관리

```javascript
// 레플리카셋 초기화
rs.initiate({
  _id: "myReplicaSet",
  members: [
    { _id: 0, host: "mongo1:27017" },
    { _id: 1, host: "mongo2:27017" },
    { _id: 2, host: "mongo3:27017" },
  ],
});

// 레플리카셋 상태 확인
rs.status();
rs.conf();

// 멤버 추가
rs.add("mongo4:27017");
rs.add({ host: "mongo4:27017", priority: 0.5 });

// 멤버 제거
rs.remove("mongo4:27017");

// 프라이머리/세컨더리 정보
rs.isMaster();
db.hello();

// 읽기 설정 변경
rs.secondaryOk(); // 세컨더리에서 읽기 허용
db.getMongo().setReadPref("secondary");
```

## 16. 샤딩 관리

```javascript
// 샤딩 활성화
sh.enableSharding("myDatabase");

// 컬렉션 샤딩
sh.shardCollection("myDatabase.users", { userId: 1 });

// 샤드 상태 확인
sh.status();

// 샤드 추가
sh.addShard("shard1/mongo1:27017,mongo2:27017,mongo3:27017");

// 밸런서 제어
sh.startBalancer();
sh.stopBalancer();
sh.isBalancerRunning();

// 청크 정보
db.chunks.find();
```

## 17. 성능 모니터링 및 프로파일링

```javascript
// 프로파일링 활성화
db.setProfilingLevel(2); // 모든 작업 기록
db.setProfilingLevel(1, { slowms: 100 }); // 100ms 이상 작업만 기록

// 프로파일 데이터 확인
db.system.profile.find().limit(5).sort({ ts: -1 }).pretty();

// 현재 작업 확인
db.currentOp();

// 느린 작업 중단
db.killOp(operationId);

// 서버 상태
db.serverStatus();
db.stats();

// 컬렉션 통계
db.users.stats();

// 인덱스 사용률
db.users.aggregate([{ $indexStats: {} }]);

// 연결 정보
db.adminCommand("connPoolStats");

// 복제 지연 확인
rs.printReplicationInfo();
rs.printSecondaryReplicationInfo();
```

## 18. 백업 및 복구

```bash
# mongodump - 논리적 백업
mongodump --host localhost:27017 --db myDatabase --out /backup/
mongodump --host localhost:27017 --collection users --db myDatabase --out /backup/

# 압축 백업
mongodump --host localhost:27017 --db myDatabase --gzip --out /backup/

# 인증이 필요한 경우
mongodump --host localhost:27017 --username myUser --password --authenticationDatabase admin --db myDatabase --out /backup/

# mongorestore - 복구
mongorestore --host localhost:27017 --db myDatabase /backup/myDatabase/
mongorestore --host localhost:27017 --db newDatabase /backup/myDatabase/

# 특정 컬렉션만 복구
mongorestore --host localhost:27017 --db myDatabase --collection users /backup/myDatabase/users.bson

# 덮어쓰기 복구
mongorestore --host localhost:27017 --db myDatabase --drop /backup/myDatabase/

# mongoexport/mongoimport - JSON/CSV 형식
mongoexport --host localhost:27017 --db myDatabase --collection users --out users.json
mongoexport --host localhost:27017 --db myDatabase --collection users --type=csv --fields name,email,age --out users.csv

mongoimport --host localhost:27017 --db myDatabase --collection users --file users.json
mongoimport --host localhost:27017 --db myDatabase --collection users --type=csv --headerline --file users.csv
```

## 19. GridFS (대용량 파일 저장)

```javascript
// GridFS 사용 (mongofiles 도구)
// 파일 업로드
// mongofiles --db myDatabase put myfile.pdf

// 파일 목록
// mongofiles --db myDatabase list

// 파일 다운로드
// mongofiles --db myDatabase get myfile.pdf

// JavaScript에서 GridFS 사용 (드라이버 필요)
// const bucket = new GridFSBucket(db, {bucketName: 'files'});

// GridFS 컬렉션 확인
db.fs.files.find();
db.fs.chunks.find();

// GridFS 파일 삭제
db.fs.files.deleteOne({ filename: "myfile.pdf" });
```

## 20. 트랜잭션 (MongoDB 4.0+)

```javascript
// 세션 시작
const session = db.getMongo().startSession();

// 트랜잭션 시작
session.startTransaction();

try {
  // 여러 작업 수행
  db.accounts.updateOne(
    { _id: "account1" },
    { $inc: { balance: -100 } },
    { session: session }
  );

  db.accounts.updateOne(
    { _id: "account2" },
    { $inc: { balance: 100 } },
    { session: session }
  );

  // 커밋
  session.commitTransaction();
} catch (error) {
  // 롤백
  session.abortTransaction();
  throw error;
} finally {
  session.endSession();
}

// 트랜잭션 with 콜백 (권장)
db.getMongo()
  .startSession()
  .withTransaction(() => {
    db.accounts.updateOne({ _id: "account1" }, { $inc: { balance: -100 } });
    db.accounts.updateOne({ _id: "account2" }, { $inc: { balance: 100 } });
  });
```

## 21. 데이터 유효성 검사

```javascript
// 스키마 유효성 검사 규칙 설정
db.createCollection("products", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "price"],
      properties: {
        name: {
          bsonType: "string",
          description: "must be a string and is required",
        },
        price: {
          bsonType: "number",
          minimum: 0,
          description: "must be a positive number and is required",
        },
        category: {
          enum: ["electronics", "clothing", "books"],
          description: "must be one of the enum values",
        },
      },
    },
  },
  validationLevel: "strict",
  validationAction: "error",
});

// 기존 컬렉션에 유효성 검사 추가
db.runCommand({
  collMod: "users",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["email"],
      properties: {
        email: {
          bsonType: "string",
          pattern: "^.+@.+$",
          description: "must be a valid email address",
        },
      },
    },
  },
});
```

## 22. 시계열 데이터 (MongoDB 5.0+)

```javascript
// 시계열 컬렉션 생성
db.createCollection("weather", {
  timeseries: {
    timeField: "timestamp",
    metaField: "metadata",
    granularity: "hours",
  },
});

// 시계열 데이터 삽입
db.weather.insertMany([
  {
    timestamp: new Date("2023-01-01T00:00:00Z"),
    metadata: { sensorId: "sensor1", location: "Seoul" },
    temperature: 15.5,
    humidity: 60,
  },
  {
    timestamp: new Date("2023-01-01T01:00:00Z"),
    metadata: { sensorId: "sensor1", location: "Seoul" },
    temperature: 16.2,
    humidity: 58,
  },
]);

// 시계열 집계
db.weather.aggregate([
  {
    $match: {
      timestamp: {
        $gte: new Date("2023-01-01"),
        $lt: new Date("2023-01-02"),
      },
    },
  },
  {
    $group: {
      _id: {
        $dateToString: {
          format: "%Y-%m-%d %H:00",
          date: "$timestamp",
        },
      },
      avgTemp: { $avg: "$temperature" },
      maxTemp: { $max: "$temperature" },
      minTemp: { $min: "$temperature" },
    },
  },
]);
```

## 23. 암호화 및 보안

```javascript
// 필드 레벨 암호화 (MongoDB 4.2+)
// 클라이언트 측 자동 암호화 설정이 필요

// 연결 시 SSL/TLS 사용
// mongosh "mongodb://localhost:27017/mydb?ssl=true&sslCAFile=/path/to/ca.pem"

// IP 화이트리스트 확인
db.adminCommand({ getParameter: 1, bind_ip: 1 });

// 감사 로그 확인 (Enterprise)
// db.adminCommand({getParameter: 1, auditLog: 1})

// 사용자 세션 확인
db.aggregate([
  { $currentOp: { allUsers: true } },
  { $match: { active: true } },
]);
```

## 24. 유틸리티 함수 및 팁

```javascript
// ObjectId 생성 및 조작
var objectId = new ObjectId();
print(objectId.getTimestamp()); // 생성 시간 추출

// 날짜 범위로 ObjectId 쿼리
var start = ObjectId(
  Math.floor(new Date("2023-01-01") / 1000).toString(16) + "0000000000000000"
);
var end = ObjectId(
  Math.floor(new Date("2023-02-01") / 1000).toString(16) + "0000000000000000"
);
db.collection.find({ _id: { $gte: start, $lt: end } });

// 대량 연산 (Bulk Operations)
var bulk = db.users.initializeUnorderedBulkOp();
bulk.insert({ name: "User1", age: 25 });
bulk.find({ name: "User2" }).update({ $set: { age: 30 } });
bulk.find({ name: "User3" }).remove();
bulk.execute();

// 랜덤 문서 샘플링
db.users.aggregate([{ $sample: { size: 5 } }]);

// 컬렉션 복사
db.users.aggregate([{ $out: "users_backup" }]);

// 데이터 타입 변환
db.users.updateMany({ age: { $type: "string" } }, [
  { $set: { age: { $toInt: "$age" } } },
]);

// 중복 제거
db.users.aggregate([
  {
    $group: {
      _id: "$email",
      doc: { $first: "$$ROOT" },
    },
  },
  { $replaceRoot: { newRoot: "$doc" } },
  { $out: "users_unique" },
]);

// 메모리 사용량 확인
db.runCommand({ collStats: "users", indexDetails: true });

// 연결 풀 상태
db.adminCommand("connPoolStats");
```

## 25. 일반적인 작업 예제

```javascript
// 페이징 (커서 기반)
// 첫 페이지
db.posts.find().sort({ _id: 1 }).limit(10);

// 다음 페이지 (마지막 _id 기억)
var lastId = ObjectId("...");
db.posts
  .find({ _id: { $gt: lastId } })
  .sort({ _id: 1 })
  .limit(10);

// 검색 기능
db.articles.createIndex({ title: "text", content: "text" });
db.articles
  .find({
    $text: { $search: "mongodb tutorial" },
    status: "published",
  })
  .sort({ score: { $meta: "textScore" } });

// 카테고리별 통계
db.products.aggregate([
  {
    $group: {
      _id: "$category",
      count: { $sum: 1 },
      avgPrice: { $avg: "$price" },
      totalValue: { $sum: { $multiply: ["$price", "$quantity"] } },
    },
  },
  { $sort: { totalValue: -1 } },
]);

// 사용자 활동 분석
db.users.aggregate([
  {
    $lookup: {
      from: "orders",
      localField: "_id",
      foreignField: "userId",
      as: "orders",
    },
  },
  {
    $addFields: {
      orderCount: { $size: "$orders" },
      totalSpent: { $sum: "$orders.amount" },
    },
  },
  { $match: { orderCount: { $gt: 0 } } },
  { $sort: { totalSpent: -1 } },
]);

// 로그 분석
db.logs.aggregate([
  {
    $match: {
      timestamp: { $gte: new Date("2023-01-01") },
      level: "ERROR",
    },
  },
  {
    $group: {
      _id: {
        hour: { $hour: "$timestamp" },
        service: "$service",
      },
      count: { $sum: 1 },
    },
  },
  { $sort: { "_id.hour": 1 } },
]);
```
