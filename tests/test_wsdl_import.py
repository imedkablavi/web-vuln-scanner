from __future__ import annotations

import pytest

from core.wsdl_import import import_wsdl_data


WSDL = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
             xmlns:tns="urn:test"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="urn:test">
  <types>
    <xsd:schema targetNamespace="urn:test">
      <xsd:element name="GetUserRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="id" type="xsd:int"/>
            <xsd:element name="filter" minOccurs="0">
              <xsd:complexType>
                <xsd:sequence>
                  <xsd:element name="name" type="xsd:string" minOccurs="0"/>
                  <xsd:element name="enabled" type="xsd:boolean"/>
                </xsd:sequence>
              </xsd:complexType>
            </xsd:element>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>
  <message name="GetUserInput">
    <part name="parameters" element="tns:GetUserRequest"/>
  </message>
  <portType name="UserPortType">
    <operation name="GetUser">
      <input message="tns:GetUserInput"/>
    </operation>
  </portType>
  <binding name="UserBinding" type="tns:UserPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="GetUser">
      <soap:operation soapAction="urn:test/GetUser"/>
    </operation>
  </binding>
  <service name="UserService">
    <port name="UserPort" binding="tns:UserBinding">
      <soap:address location="https://example.com/soap"/>
    </port>
  </service>
</definitions>
"""


def test_wsdl_import_builds_inventory_only_surface_and_nested_xsd_paths():
    surfaces, summary = import_wsdl_data(WSDL, target="https://example.com")

    assert summary["surfaces"] == 1
    assert summary["active_eligible"] == 0
    assert summary["replayed_requests"] == 0
    surface = surfaces[0]
    assert surface.url == "https://example.com/soap"
    assert surface.method == "POST"
    assert surface.source == "wsdl"
    assert surface.meta["operation"] == "GetUser"
    assert surface.meta["soap_action"] == "urn:test/GetUser"
    assert surface.meta["content_type"] == "text/xml"
    assert surface.meta["active_eligible"] is False

    by_path = {item.path: item for item in surface.inputs}
    assert "/Envelope/Body/GetUser/GetUserRequest/id" in by_path
    assert "/Envelope/Body/GetUser/GetUserRequest/filter/name" in by_path
    assert "/Envelope/Body/GetUser/GetUserRequest/filter/enabled" in by_path
    assert by_path["/Envelope/Body/GetUser/GetUserRequest/id"].value == 1
    assert by_path["/Envelope/Body/GetUser/GetUserRequest/filter/enabled"].value is True
    assert by_path["/Envelope/Body/GetUser/GetUserRequest/filter/name"].required is False


def test_wsdl_import_rejects_out_of_scope_service_address():
    raw = WSDL.replace("https://example.com/soap", "https://outside.invalid/soap")
    surfaces, summary = import_wsdl_data(raw, target="https://example.com")

    assert surfaces == []
    assert summary["skipped"]["out_of_scope"] == 1


def test_wsdl_import_rejects_dtd_and_entity_declarations():
    raw = """<!DOCTYPE definitions [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"/>"""
    with pytest.raises(ValueError, match="DTD/ENTITY"):
        import_wsdl_data(raw, target="https://example.com")


def test_wsdl_import_detects_soap12_binding_and_content_type():
    raw = WSDL.replace(
        '<soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>',
        '<soap12:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>',
    ).replace(
        '<soap:operation soapAction="urn:test/GetUser"/>',
        '<soap12:operation soapAction="urn:test/GetUser"/>',
    ).replace(
        '<soap:address location="https://example.com/soap"/>',
        '<soap12:address location="https://example.com/soap"/>',
    )
    surfaces, _summary = import_wsdl_data(raw, target="https://example.com")

    assert surfaces[0].meta["soap_version"] == "1.2"
    assert surfaces[0].meta["content_type"] == "application/soap+xml"
