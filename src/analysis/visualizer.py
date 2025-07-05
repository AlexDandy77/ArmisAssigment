import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pandas import Timestamp
from pandas._libs import NaTType
from pymongo.database import Database
from datetime import datetime, timedelta, timezone


class AssetVisualizer:
    OUTPUT_DIR = "visualizations"

    def __init__(self, db: Database):
        self.collection = db["unified_assets"]
        if not os.path.exists(self.OUTPUT_DIR):
            os.makedirs(self.OUTPUT_DIR)
        print(f"Visualizations will be saved to the '{self.OUTPUT_DIR}/' directory.")

    def _get_latest_seen_timestamp(self, doc: dict) -> Timestamp | NaTType:
        qualys_sec = doc.get('qualys_security', {})
        crowdstrike_sec = doc.get('crowdstrike_security', {})

        qualys_seen = qualys_sec.get('last_checked_in') if qualys_sec else None
        crowdstrike_seen = crowdstrike_sec.get('last_seen') if crowdstrike_sec else None

        # Convert string dates to datetime objects
        ts_qualys = pd.to_datetime(qualys_seen, errors='coerce', utc=True)
        ts_crowdstrike = pd.to_datetime(crowdstrike_seen, errors='coerce', utc=True)

        # Return most recent valid timestamp
        if pd.notna(ts_qualys) and pd.notna(ts_crowdstrike):
            return max(ts_qualys, ts_crowdstrike)
        elif pd.notna(ts_qualys):
            return ts_qualys
        elif pd.notna(ts_crowdstrike):
            return ts_crowdstrike
        else:
            return pd.NaT

    def fetch_and_prepare_data(self) -> pd.DataFrame:
        print("Fetching and preparing data from MongoDB...")
        all_hosts = list(self.collection.find({}))
        if not all_hosts:
            print("Warning: No data found in the 'unified_assets' collection.")
            return pd.DataFrame()

        df = pd.DataFrame(all_hosts)

        df['last_seen'] = df.apply(self._get_latest_seen_timestamp, axis=1)

        print(f"Successfully loaded {len(df)} hosts into DataFrame.")
        return df

    def generate_os_distribution_chart(self, df: pd.DataFrame):
        if 'os_platform' not in df or df['os_platform'].isnull().all():
            print("Skipping OS distribution chart: 'os_platform' column is missing or empty.")
            return

        print("Generating OS distribution chart...")
        plt.figure(figsize=(12, 8))

        sns.countplot(y=df['os_platform'], order=df['os_platform'].value_counts().index, palette="viridis", hue=df['os_platform'], legend=False)

        plt.title('Distribution of Hosts by Operating System', fontsize=16, weight='bold')
        plt.xlabel('Number of Hosts', fontsize=12)
        plt.ylabel('Operating System', fontsize=12)
        plt.xticks(fontsize=10)
        plt.yticks(fontsize=10)
        plt.tight_layout()

        save_path = os.path.join(self.OUTPUT_DIR, "os_distribution.png")
        plt.savefig(save_path)
        plt.close()
        print(f"Chart saved to: {save_path}")

    def generate_host_activity_chart(self, df: pd.DataFrame):
        if 'last_seen' not in df or df['last_seen'].isnull().all():
            print("Skipping host activity chart: 'last_seen' column is missing or empty.")
            return

        print("Generating host activity chart (Active vs. Stale)...")


        # Define the threshold for what is considered "stale"
        #start_date = datetime.now(timezone.utc)
        # thirty_days_ago = start_date - timedelta(days=30) # From now

        start_date = datetime.strptime('2023-07-27', '%Y-%m-%d').replace(tzinfo=timezone.utc) # From 2023-07-27
        thirty_days_ago = start_date - timedelta(days=30)

        # Categorize hosts
        df['activity_status'] = df['last_seen'].apply(
            lambda ts: 'Stale (>30 days)' if pd.notna(ts) and ts < thirty_days_ago else 'Active (<=30 days)'
        )

        plt.figure(figsize=(8, 6))
        sns.countplot(x=df['activity_status'], order=['Active (<=30 days)', 'Stale (>30 days)'], palette="coolwarm", hue=df['activity_status'], legend=False)

        plt.title(f'Host Activity: Active vs. Stale. Current date: {start_date.date()}', fontsize=16, weight='bold')
        plt.xlabel('Activity Status', fontsize=12)
        plt.ylabel('Number of Hosts', fontsize=12)
        plt.xticks(fontsize=10)
        plt.yticks(fontsize=10)
        plt.tight_layout()

        save_path = os.path.join(self.OUTPUT_DIR, "host_activity.png")
        plt.savefig(save_path)
        plt.close()
        print(f"Chart saved to: {save_path}")

    def generate_network_segment_chart(self, df: pd.DataFrame):
        if 'default_gateway' not in df or df['default_gateway'].isnull().all():
            print("Skipping network segment chart: 'default_gateway' column is missing or empty.")
            return

        print("Generating host count by network segment chart...")

        # Count hosts per gateway, dropping nulls
        gateway_counts = df.dropna(subset=['default_gateway'])['default_gateway'].value_counts()

        # Adjust number to filter for networks with more than some device number in a network
        significant_networks = gateway_counts[gateway_counts >= 1]

        if significant_networks.empty:
            print("No significant network segments (more than 1 host per gateway) found to visualize.")
            return

        # Plot the top 5 largest networks
        top_networks = significant_networks.head(5).sort_values(ascending=True)

        plt.figure(figsize=(12, 8))

        ax = sns.barplot(x=top_networks.values, y=top_networks.index, palette='plasma', hue=top_networks.index, legend=False)

        plt.title('Host Count by Network Segment (Top 5)', fontsize=16, weight='bold')
        plt.xlabel('Number of Hosts', fontsize=12)
        plt.ylabel('Default Gateway IP', fontsize=12)

        # Ensure integer ticks on the x-axis for clarity
        max_count = top_networks.max()
        if max_count < 10:
            ax.set_xticks(range(int(max_count) + 2))

        plt.tight_layout()

        save_path = os.path.join(self.OUTPUT_DIR, "network_segment_distribution.png")
        plt.savefig(save_path)
        plt.close()
        print(f"Chart saved to: {save_path}")

    def run_analysis(self):
        df = self.fetch_and_prepare_data()
        if df.empty:
            return

        self.generate_os_distribution_chart(df)
        self.generate_host_activity_chart(df)
        self.generate_network_segment_chart(df)
        print("\nAnalysis complete.")

