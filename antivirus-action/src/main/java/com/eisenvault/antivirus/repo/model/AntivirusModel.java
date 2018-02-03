package com.eisenvault.antivirus.repo.model;

import org.alfresco.service.namespace.QName;

public class AntivirusModel {

	/*
	 * Namespace model
	 */
	public static final String NAMESPACE_ANTIVIRUS_CONTENT_MODEL = "http://www.eisenvault.com/model/antivirus/1.0";

	/*
	 * Aspects
	 */
	public static final QName ASPECT_INFECTED = QName.createQName(
			NAMESPACE_ANTIVIRUS_CONTENT_MODEL, "infected");
	/*
	 * Properties
	 */
	public static final QName PROP_INFECTED_DATE = QName.createQName(
			NAMESPACE_ANTIVIRUS_CONTENT_MODEL, "date");
	public static final QName PROP_INFECTED_CLEAN = QName.createQName(
			NAMESPACE_ANTIVIRUS_CONTENT_MODEL, "clean");
	
}
