# blind sql

- `1 UNION SELECT 1,2,3` 식으로 컬럼 수를 에러 메시지로 맞춰가고, `information_schema`를 거쳐 DB명·테이블·컬럼·크리덴셜까지 뽑는 UNION 기반 SQL 인젝션 실습 과정
- 인젝션 포인트가 확인되고 에러 메시지나 결과가 화면에 보일 때, ID를 `0`으로 만들어 원래 결과를 비우고 UNION 결과를 출력시키는 단계부터 진행할 때
- 쿼리 결과(또는 에러)가 페이지에 출력되어야 하고, DBMS가 MySQL로 `information_schema` 접근이 막혀 있지 않아야 한다. 원래 레코드가 먼저 반환되지 않도록 `0 UNION ...`으로 조건을 비운다

1 UNION SELECT 1

This statement should produce an error message informing you that the UNION SELECT statement has a different number of columns than the original SELECT query. So let's try again but add another column:

1 UNION SELECT 1,2

Same error again, so let's repeat by adding another column:

1 UNION SELECT 1,2,3

Success, the error message has gone, and the article is being displayed, but now we want to display our data instead of the article. The article is displayed because it takes the first returned result somewhere in the website's code and shows that. To get around that, we need the first query to produce no results. This can simply be done by changing the article ID from 1 to 0.

0 UNION SELECT 1,2,3

You'll now see the article is just made up of the result from the UNION select, returning the column values 1, 2, and 3. We can start using these returned values to retrieve more useful information. First, we'll get the database name that we have access to:

0 UNION SELECT 1,2,database()

You'll now see where the number 3 was previously displayed; it now shows the name of the database, which is sqli_one.

Our next query will gather a list of tables that are in this database.

0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'

There are a couple of new things to learn in this query. Firstly, the method group_concat() gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas. The next thing is the information_schema database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to. In this particular query, we're interested in listing all the tables in the sqli_one database, which is article and staff_users.

As the first level aims to discover Martin's password, the staff_users table is what interests us. We can utilise the information_schema database again to find the structure of this table using the below query.

0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'

This is similar to the previous SQL query. However, the information we want to retrieve has changed from table_name to column_name, the table we are querying in the information_schema database has changed from tables to columns, and we're searching for any rows where the table_name column has a value of staff_users.

The query results provide three columns for the staff_users table: id, password, and username. We can use the username and password columns for our following query to retrieve the user's information.

0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users

Again, we use the group_concat method to return all of the rows into one string and make it easier to read. We've also added ,':', to split the username and password from each other. Instead of being separated by a comma, we've chosen the HTML <br> tag that forces each result to be on a separate line to make for easier reading.

You should now have access to Martin's password to enter and move to the next level.
