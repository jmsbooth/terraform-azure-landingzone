variable "subscription_id" {}
variable "client_id" {}
variable "client_certificate_path" {}
variable "client_certificate_password" {}
variable "tenant_id" {}
variable "deployment_location" {}
variable "deployment_system" {}

terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "3.16.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }

  subscription_id             = var.subscription_id
  client_id                   = var.client_id
  client_certificate_path     = var.client_certificate_path
  client_certificate_password = var.client_certificate_password
  tenant_id                   = var.tenant_id
}

data "azurerm_client_config" "current" {}

##Landing_Zone Resources

# management-group
resource "azurerm_management_group" "system" {
  display_name = "mgmt-group-${var.deployment_system}"
}

#   resource groups
resource "azurerm_resource_group" "mgmt" {
  name     = "${var.deployment_system}-mgmt"
  location = var.deployment_location
}

resource "azurerm_resource_group" "system" {
  name     = "${var.deployment_system}-system"
  location = var.deployment_location
}

resource "azurerm_resource_group" "storage" {
  name     = "${var.deployment_system}-storage"
  location = var.deployment_location
}

resource "azurerm_resource_group" "security" {
  name     = "${var.deployment_system}-system"
  location = var.deployment_location
}


#   virtual-network
resource "azurerm_network_security_group" "mgmt-net" {
  name                = "${var.deployment_system}-mgmt-net-security-group"
  location            = azurerm_resource_group.mgmt.location
  resource_group_name = azurerm_resource_group.mgmt.name
}

resource "azurerm_network_ddos_protection_plan" "main_ddos" {
  count = var.create_ddos_plan ? 1:0
  name = "ddos_protection_plan"
  location = var.deployment_location
  resource_group_name = azurerm_resource_group.mgmt.name
}

resource "azurerm_virtual_network" "mgmt-net" {
  name                = "${var.deployment_system}-mgmt-network"
  location            = azurerm_resource_group.mgmt.location
  resource_group_name = azurerm_resource_group.mgmt.name
  address_space       = ["10.0.0.0/16"]
  dns_servers         = ["10.0.0.4", "10.0.0.5"]
  
  dynamic "ddos_protection_plan" {
    for_each = var.create_ddos_plan == true ? range(1):range(0)
    iterator = v
    content {
      id = azurerm_network_ddos_protection_plan.main_ddos[0].id
      enable = true
    }
  }

  subnet {
    name           = "${var.deployment_system}-internal"
    address_prefix = "10.0.1.0/24"
  }

  subnet {
    name           = "${var.deployment_system}-external"
    address_prefix = "10.0.2.0/24"
    security_group = azurerm_network_security_group.mgmt.id
  }

  tags = {
    environment = "Production"
  }
}

resource "azurerm_virtual_network_peering" "mgmt-net" {
  name                      = "${var.deployment_system}-peering"
  resource_group_name       = azurerm_resource_group.mgmt.name
  virtual_network_name      = azurerm_virtual_network.mgmt.name
  remote_virtual_network_id = azurerm_virtual_network.SACA.id #change this to the name of the corporate hub vnet
}

resource "azurerm_network_security_group" "mgmt-net" {
  name                = "${var.deployment_system}-NetSecurityGroupp"
  location            = azurerm_resource_group.mgmt.location
  resource_group_name = azurerm_resource_group.mgmt.name

#   Populate with Firewall rules
  security_rule {
    name                       = "test123"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    environment = "Production"
  }
}


#   network watcher
resource "azurerm_network_watcher" "mgmt-netwatcher" {
  name                = "${var.deployment_system}-production-nwwatcher"
  location            = azurerm_resource_group.mgmt.location
  resource_group_name = azurerm_resource_group.mgmt.name
}


#   policy manager
###   need to create more policies
resource "azurerm_policy_definition" "allow-deploy-azuregov" {
  name                = "only-deploy-in-azuregov"
  policy_type         = "Custom"
  mode                = "All"
  display_name        = "my-policy-definition"
  management_group_id = azurerm_management_group.system.id

  policy_rule = <<POLICY_RULE
    {
    "if": {
      "not": {
        "field": "location",
        "contains": "*gov"
      }
    },
    "then": {
      "effect": "Deny"
    }
  }
POLICY_RULE
}

resource "azurerm_management_group_policy_assignment" "example" {
  name                 = "allow-azuregov-policy"
  policy_definition_id = azurerm_policy_definition.allow-deploy-azuregov.id
  management_group_id  = azurerm_management_group.system.id
}


#   storage account
resource "azurerm_storage_account" "system-storage" {
  name                     = "${var.deployment_system}-storage"
  resource_group_name      = azurerm_resource_group.storage.name
  location                 = azurerm_resource_group.storage.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version = "TLS1_2"

  tags = {
    environment = "Production"
  }
}

### Other storage resources will be deployed using the system terraform file, not the landing zone file.

#   key vault
### need to better understand keys in order to build better.
### hosted solutions are responsible for generating their own certs via terraform. Below certs are for mgmt only. 
resource "azurerm_key_vault" "keyvault" {
  name                        = "${var.deployment_system}-keyvault"
  location                    = azurerm_resource_group.mgmt.location
  resource_group_name         = azurerm_resource_group.mgmt.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
    ]

    secret_permissions = [
      "Get",
    ]

    storage_permissions = [
      "Get",
    ]
  }
}

resource "azurerm_key_vault_certificate" "mgmt-certificate" {
  name         = "generated-cert"
  key_vault_id = azurerm_key_vault.keyvault.id

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        days_before_expiry = 30
      }
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      # Server Authentication = 1.3.6.1.5.5.7.3.1
      # Client Authentication = 1.3.6.1.5.5.7.3.2
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]

      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]

      subject_alternative_names {
        dns_names = ["internal.contoso.com", "domain.hello.world"]
      }

      subject            = "CN=hello-world"
      validity_in_months = 12
    }
  }
}

#   logging resources/sidecar


#   security center resources

