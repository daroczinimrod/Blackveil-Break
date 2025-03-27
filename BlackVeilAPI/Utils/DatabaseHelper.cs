namespace BlackVeilAPI.Utils
{
    using MySql.Data.MySqlClient;
    using System.Data;

    public class DatabaseHelper
    {
        private readonly string _connectionString;

        public DatabaseHelper(string connectionString)
        {
            if (!connectionString.Contains("Database=") && !connectionString.Contains("Initial Catalog="))
            {
                _connectionString = connectionString + "Database=blackveildb;";
            }
            else
            {
                _connectionString = connectionString;
            }
        }
        public async Task<T> ExecuteScalarAsync<T>(string query, MySqlParameter[] parameters)
        {
            using (var connection = new MySqlConnection(_connectionString))
            {
                await connection.OpenAsync();
                using (var command = new MySqlCommand(query, connection))
                {
                    command.Parameters.AddRange(parameters);
                    var result = await command.ExecuteScalarAsync();
                    return (T)Convert.ChangeType(result, typeof(T));
                }
            }
        }
        public async Task<DataTable> ExecuteQueryAsync(string query, MySqlParameter[] parameters = null)
        {
            using var connection = new MySqlConnection(_connectionString);
            using var command = new MySqlCommand(query, connection);
            if (parameters != null)
                command.Parameters.AddRange(parameters);

            var dataTable = new DataTable();
            await connection.OpenAsync();
            using var reader = await command.ExecuteReaderAsync();
            dataTable.Load(reader);
            return dataTable;
        }
        public async Task<int> ExecuteNonQueryAsync(string query, MySqlParameter[] parameters = null)
        {
            using var connection = new MySqlConnection(_connectionString);
            using var command = new MySqlCommand(query, connection);
            if (parameters != null)
                command.Parameters.AddRange(parameters);

            await connection.OpenAsync();
            return await command.ExecuteNonQueryAsync();
        }
    }
}
