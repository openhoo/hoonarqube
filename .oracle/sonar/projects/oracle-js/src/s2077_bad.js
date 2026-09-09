import pg from 'pg';
function run(name, column) {
    const client = new pg.Client();
    client.query(`SELECT * FROM users WHERE name = ${name}`);
    return client.query('SELECT ' + column);
}
