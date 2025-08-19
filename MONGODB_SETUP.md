# MongoDB Atlas Setup Guide for PhishGuard MVP

## Step 1: Create MongoDB Atlas Account

1. Go to [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Sign up for a free account
3. Create a new cluster (choose the free M0 tier)
4. Select a cloud provider and region close to you
5. Wait for cluster creation (2-5 minutes)

## Step 2: Configure Database Access

1. **Create Database User:**
   - Go to "Database Access" in the left sidebar
   - Click "Add New Database User"
   - Choose "Password" authentication
   - Create username and strong password
   - Set role to "Atlas Admin" (or "Read and write to any database")
   - Click "Add User"

2. **Configure Network Access:**
   - Go to "Network Access" in the left sidebar
   - Click "Add IP Address"
   - Choose "Add Current IP Address" (or "Allow Access from Anywhere" for testing)
   - Click "Confirm"

## Step 3: Get Connection String

1. Go to "Clusters" in the left sidebar
2. Click "Connect" on your cluster
3. Choose "Connect your application"
4. Select "Python" and version "3.12 or later"
5. Copy the connection string (looks like):
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/<dbname>?retryWrites=true&w=majority
   ```

## Step 4: Configure PhishGuard MVP

1. **Update your `.env` file:**
   ```env
   # Replace <username>, <password>, <cluster-url>, and <database-name>
   PHISHGUARD_MONGODB_URL=mongodb+srv://your-username:your-password@cluster0.xxxxx.mongodb.net/phishguard?retryWrites=true&w=majority
   PHISHGUARD_DATABASE_NAME=phishguard
   PHISHGUARD_USE_MONGODB=true
   ```

2. **Example configuration:**
   ```env
   # Example (replace with your actual values)
   PHISHGUARD_MONGODB_URL=mongodb+srv://phishguard_user:MySecurePassword123@cluster0.abc12.mongodb.net/phishguard?retryWrites=true&w=majority
   PHISHGUARD_DATABASE_NAME=phishguard
   PHISHGUARD_USE_MONGODB=true
   ```

## Step 5: Test Connection

Run the test script to verify everything works:

```bash
python test_mongo_connection.py
```

## MongoDB Atlas Features You Get:

✅ **Cloud Database**: No local database management
✅ **Automatic Backups**: Built-in backup and restore
✅ **Scaling**: Easily scale up as your data grows
✅ **Security**: Built-in security features and encryption
✅ **Monitoring**: Performance monitoring and alerts
✅ **Global Deployment**: Deploy in multiple regions
✅ **Free Tier**: 512MB storage, perfect for MVP

## Collections Created:

The system will automatically create these collections:

- `url_records`: Stores URLs being monitored
- `detections`: Stores phishing detection results
- `labels`: Stores human-verified labels for training

## Advantages over SQLite:

1. **Cloud-based**: No local file dependencies
2. **Concurrent Access**: Multiple instances can access same data
3. **Scalability**: Handle millions of URLs and detections
4. **Rich Queries**: Complex aggregation and filtering
5. **Real-time**: Built-in change streams for real-time updates
6. **Backup**: Automatic backups and point-in-time recovery

## Security Best Practices:

1. Use strong passwords for database users
2. Restrict IP access to known addresses
3. Enable connection encryption (automatically enabled)
4. Rotate credentials regularly
5. Monitor access logs in Atlas dashboard

## Troubleshooting:

1. **Connection Error**: Check IP whitelist and credentials
2. **Authentication Failed**: Verify username/password
3. **Timeout**: Check network connectivity
4. **Database Not Found**: Database will be created automatically on first use

## Free Tier Limits:

- Storage: 512 MB
- RAM: Shared
- Network: No bandwidth limits
- Connections: Up to 100 concurrent

Perfect for MVP development and testing!
