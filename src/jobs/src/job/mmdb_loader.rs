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

pub async fn run() -> Result<(), anyhow::Error> {
    let cfg = config::get_config();
    let data_dir = Path::new(&cfg.common.mmdb_data_dir);
    std::fs::create_dir_all(data_dir)?;
    let city = data_dir.join(MMDB_CITY_FILE_NAME);
    let asn = data_dir.join(MMDB_ASN_FILE_NAME);

    if load_table(&city, GEO_IP_CITY_ENRICHMENT_TABLE) {
        match MaxmindClient::new_with_path(city.to_string_lossy().as_ref()) {
            Ok(client) => *MAXMIND_DB_CLIENT.write().await = Some(client),
            Err(error) => log::warn!("Failed to load local MaxMind city database: {error}"),
        }
    }
    load_table(&asn, GEO_IP_ASN_ENRICHMENT_TABLE);
    Ok(())
}

fn load_table(path: &Path, table_name: &str) -> bool {
    if !path.is_file() {
        log::info!("Local MaxMind database not found: {}", path.display());
        return false;
    }
    let config = GeoipConfig {
        path: path.to_string_lossy().into_owned(),
        locale: "en".to_string(),
    };
    match Geoip::new(config) {
        Ok(table) => {
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
        assert!(!load_table(&missing, "missing_test_table"));

        let invalid = std::env::temp_dir().join(format!("invalid-{}.mmdb", config::ider::uuid()));
        std::fs::write(&invalid, b"not a maxmind database").unwrap();
        assert!(!load_table(&invalid, "invalid_test_table"));
        std::fs::remove_file(invalid).unwrap();
    }
}
