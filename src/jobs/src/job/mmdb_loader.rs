// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::path::Path;

use config::{
    GEO_IP_ASN_ENRICHMENT_TABLE, GEO_IP_CITY_ENRICHMENT_TABLE, MMDB_ASN_FILE_NAME,
    MMDB_CITY_FILE_NAME,
};
use enrichment_data::enrichment_table::geoip::{Geoip, GeoipConfig};

use crate::common::{infra::config::MAXMIND_DB_CLIENT, meta::maxmind::MaxmindClient};

pub async fn run() {
    let data_dir = config::get_config().common.mmdb_data_dir.clone();
    if let Err(error) =
        tokio::task::spawn_blocking(move || load_from_dir(Path::new(&data_dir))).await
    {
        log::warn!("Failed to join local MaxMind loader: {error}");
    }
}

fn load_from_dir(data_dir: &Path) {
    let city = data_dir.join(MMDB_CITY_FILE_NAME);
    let asn = data_dir.join(MMDB_ASN_FILE_NAME);

    load_table(&city, GEO_IP_CITY_ENRICHMENT_TABLE, true);
    load_table(&asn, GEO_IP_ASN_ENRICHMENT_TABLE, false);
}

fn load_table(path: &Path, table_name: &str, set_city_client: bool) -> bool {
    if !path.is_file() {
        log::info!("Local MaxMind database not found: {}", path.display());
        return false;
    }
    let config = GeoipConfig {
        path: path.to_string_lossy().into_owned(),
        ..GeoipConfig::default()
    };
    match Geoip::new(config) {
        Ok(table) => {
            if set_city_client {
                let client = MaxmindClient::new_with_shared_reader(table.reader());
                *MAXMIND_DB_CLIENT.blocking_write() = Some(client);
            }
            transform::register_global_enrichment_table(table_name, table);
            true
        }
        Err(error) => {
            log::warn!(
                "Failed to load local MaxMind database {}: {error}",
                path.display()
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_invalid_local_database_is_not_registered() {
        let missing = std::path::PathBuf::from("/path/that/does/not/exist.mmdb");
        assert!(!load_table(&missing, "missing_test_table", false));

        let invalid = std::env::temp_dir().join(format!("invalid-{}.mmdb", config::ider::uuid()));
        std::fs::write(&invalid, b"not a maxmind database").unwrap();
        assert!(!load_table(&invalid, "invalid_test_table", false));
        std::fs::remove_file(invalid).unwrap();
    }

    #[test]
    fn unusable_data_directory_does_not_fail_startup() {
        let data_dir = std::env::temp_dir().join(format!("mmdb-file-{}", config::ider::uuid()));
        std::fs::write(&data_dir, b"not a directory").unwrap();
        load_from_dir(&data_dir);
        std::fs::remove_file(data_dir).unwrap();
    }
}
