package com.eisenvault.antivirus.repo.action;

import java.util.List;
import java.io.File;
import java.io.Serializable;
import java.util.Map;
import java.util.HashMap;

import org.alfresco.model.ContentModel;

import org.alfresco.service.namespace.QName;
import org.alfresco.error.AlfrescoRuntimeException;

import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.dictionary.DataTypeDefinition;
import org.alfresco.service.cmr.action.ActionService;
import org.alfresco.repo.action.ParameterDefinitionImpl;
import org.alfresco.repo.action.executer.ActionExecuterAbstractBase;
import org.alfresco.repo.action.executer.MailActionExecuter;
import org.alfresco.repo.content.MimetypeMap;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.ContentWriter;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.repository.StoreRef;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.cmr.version.Version;
import org.alfresco.service.cmr.version.VersionService;
import org.alfresco.service.cmr.version.VersionType;
import org.alfresco.service.cmr.search.SearchService;
import org.alfresco.service.cmr.site.SiteInfo;
import org.alfresco.service.cmr.site.SiteService;
import org.alfresco.repo.version.VersionModel;
import org.alfresco.service.cmr.search.ResultSet;

import org.alfresco.util.TempFileProvider;
import org.alfresco.util.exec.RuntimeExec;
import org.alfresco.util.exec.RuntimeExec.ExecutionResult;
import org.apache.log4j.Logger;

import com.eisenvault.antivirus.repo.model.AntivirusModel;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**//**
	 * action executer
	 * 
	 * @author Swithun Crowe
	 */
public class AntivirusActionExecuter extends ActionExecuterAbstractBase {
	/**
	 * Action constants
	 */
	public static final String NAME = "antivirus-action";
	public static final String VAR_SOURCE = "source";
	public static final String TEXT = "This file is infected";
	private final Logger logger = Logger.getLogger(AntivirusActionExecuter.class);

	private ContentService contentService;
	private NodeService nodeService;
	private ActionService actionService;
	private PersonService personService;
	private RuntimeExec command;
	private VersionService versionService;
	private SearchService searchService;
	private SiteService siteService;
	/**
	 * @param contentService
	 *            The contentService to set.
	 */
	public void setContentService(ContentService contentService) {
		this.contentService = contentService;
	}

	/**
	 * @param nodeService
	 *            The nodeService to set.
	 */
	public void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}

	/**
	 * @param actionService
	 *            The actionService to set.
	 */
	public void setActionService(ActionService actionService) {
		this.actionService = actionService;
	}

	/**
	 * @param personService
	 *            The personService to set.
	 */
	public void setPersonService(PersonService personService) {
		this.personService = personService;
	}

	/**
	 * @param fromEmail
	 *            The email address that messages are sent from
	 */
	

	/**
	 * @param command
	 *            The antivirus command
	 */
	public void setCommand(RuntimeExec command) {
		this.command = command;
	}

	public void setVersionService(VersionService versionService) {
		this.versionService = versionService;
	}
	
	public void setSearchService(SearchService searchService) {
		this.searchService = searchService;
	}
	
	public void setsiteService(SiteService siteService) {
		this.siteService = siteService;
	}
	
	@Override
	public void init() {
		super.init();
	}

	@Override
	protected void addParameterDefinitions(List<ParameterDefinition> paramList) {
		 paramList.add(new ParameterDefinitionImpl("a-parameter", DataTypeDefinition.TEXT, false, getParamDisplayLabel("a-parameter")));      
		// no params
	}

	@Override
	protected void executeImpl(final Action ruleAction, final NodeRef actionedUponNodeRef) {
		// put content into temp file
		ContentReader reader = contentService.getReader(actionedUponNodeRef, ContentModel.PROP_CONTENT);

		String fileName = (String) nodeService.getProperty(actionedUponNodeRef, ContentModel.PROP_NAME);
		File sourceFile = TempFileProvider.createTempFile("anti_virus_check", "_" + fileName);
		reader.getContent(sourceFile);

		// add the source property
		Map<String, String> properties = new HashMap<String, String>(5);
		properties.put(VAR_SOURCE, sourceFile.getAbsolutePath());

		// execute the transformation command
		ExecutionResult result = null;
		try {
			if (!nodeService.hasAspect(actionedUponNodeRef, AntivirusModel.ASPECT_INFECTED))
			result = command.execute(properties);
			logger.debug(result);
		} catch (Throwable e) {
			throw new AlfrescoRuntimeException("Antivirus check error: \n" + command, e);
		}

		// check
		if (!result.getSuccess()) {
			// throw new AlfrescoRuntimeException('Antivirus check error: \n' +
			// result);
			// try sending email using template
			try {		
				// try to get document creator's email address
				logger.debug("trying to get document creator's email address");
				String creatorName = (String) nodeService.getProperty(actionedUponNodeRef, ContentModel.PROP_CREATOR);
				if (null == creatorName || 0 == creatorName.length()) {
					throw new Exception("couldn't get creator's name");
				}

				NodeRef creator = personService.getPerson(creatorName);
				if (null == creator) {
					throw new Exception("couldn't get creator");
				}

				String creatorEmail = (String) nodeService.getProperty(creator, ContentModel.PROP_EMAIL);
				if (null == creatorEmail || 0 == creatorEmail.length()) {
					throw new Exception("couldn't get creator's email address");
				}
				
				/*creating new text file and writing the text in case of infected file*/
				logger.debug("Creating new text file and writing the text in case of infected file");
				ContentWriter writer=contentService.getWriter(actionedUponNodeRef, ContentModel.PROP_CONTENT, true);
				writer.setMimetype(MimetypeMap.MIMETYPE_TEXT_PLAIN);
				String txtFile = fileName+".txt";
				nodeService.setProperty(actionedUponNodeRef,ContentModel.PROP_NAME,txtFile);
				writer.putContent(TEXT);
				
				// Manual versioning because of Alfresco insane rules for first version content nodes
				logger.debug("Manual Versioning because of Alfresco insane rules for first version content nodes");
				String propDescValue = "extension and mimetype of infected file is changed";
				logger.debug(propDescValue);
				versionService.ensureVersioningEnabled(actionedUponNodeRef, null);
				Map<String, Serializable> versionProperties = new HashMap<String, Serializable>();
				versionProperties.put(Version.PROP_DESCRIPTION, propDescValue);
				versionProperties.put(VersionModel.PROP_VERSION_TYPE, VersionType.MINOR);
				versionService.createVersion(actionedUponNodeRef, versionProperties);
				
				/*Notify for the infected file to the creator and admin*/
				logger.debug("notify for the infected file to the creator and admin");
				/*fetching the document link for sending in the template*/
				String siteName, link;
				String stringNodeRef = actionedUponNodeRef.toString();
				SiteInfo siteInfo = siteService.getSite(actionedUponNodeRef);
				logger.debug("Printing siteInfo " + siteInfo);
				if(siteInfo != null){
					siteName = siteInfo.getShortName();
					logger.debug("Printing sitename " + siteName);
					link = "page/site/" + siteName
							+ "/document-details?nodeRef=" + stringNodeRef;
				}else {
					logger.debug("No siteInfo means the doc is attached externally");
					link = "page/document-details?nodeRef=" + stringNodeRef;
				}
				
				/*fetching the administrator username and useremail*/
				String adminUserName = AuthenticationUtil.getAdminUserName();
				NodeRef adminRef = personService.getPerson(adminUserName);     
				
				/*putting the parameters in the template model*/
				String templatePATH = "PATH:\"/app:company_home/app:dictionary/app:email_templates/cm:virus_found.html.ftl\"";
		        /*String firstName = nodeService.getProperty(creator, ContentModel.PROP_FIRSTNAME).toString();*/
		        String adminEmail = nodeService.getProperty(adminRef, ContentModel.PROP_EMAIL).toString();
		        Map<String, Object> templateArgs = new HashMap<String, Object>(8, 1.0f);
				templateArgs.put("filename", fileName);
				templateArgs.put("fileLink", link);
				/*templateArgs.put("firstname", firstName);*/
				/*templateArgs.put("admin", adminUserName);*/
				
				 ResultSet resultSet = searchService.query(new StoreRef(StoreRef.PROTOCOL_WORKSPACE, "SpacesStore"), SearchService.LANGUAGE_LUCENE, templatePATH);
			        if (resultSet.length()==0){
			           logger.error("--------------------------Template "+ templatePATH +" not found.");
			        }        
			        NodeRef template = resultSet.getNodeRef(0);
			        
			        Map<String, Serializable> templateModel = new HashMap<String, Serializable>();
			        templateModel.put("args",(Serializable)templateArgs);
				
				
				// sending email message
				Action emailAction = actionService.createAction("mail");
				emailAction.setParameterValue(MailActionExecuter.PARAM_TO, creatorEmail);
				emailAction.setParameterValue(MailActionExecuter.PARAM_SUBJECT, "Virus found in" + " "+fileName);
				emailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE, template);
				emailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE_MODEL,(Serializable)templateModel);
	            emailAction.setParameterValue(MailActionExecuter.PARAM_CC, adminEmail);
				emailAction.setExecuteAsynchronously(true);
				actionService.executeAction(emailAction, null);

				/* adding code for adding of aspect in case of infected file */
				logger.debug("adding the aspect to the infected file");
				Calendar cal = GregorianCalendar.getInstance();
				Date dt = cal.getTime();
				String df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(dt);

				HashMap<QName, Serializable> properties2 = new HashMap<QName, Serializable>(1, 1.0f);
				properties2.put(AntivirusModel.PROP_INFECTED_DATE, df.substring(0, 22) + ":" + df.substring(22));
				properties2.put(AntivirusModel.PROP_INFECTED_CLEAN, true);
				if (!nodeService.hasAspect(actionedUponNodeRef, AntivirusModel.ASPECT_INFECTED)) {

					nodeService.addAspect(actionedUponNodeRef, AntivirusModel.ASPECT_INFECTED, properties2);
					
				}

			} catch (Exception e) {
				throw new AlfrescoRuntimeException("Failed to send email:\n" + e.getMessage());
			}
		}
		
		else
		{
			HashMap<QName, Serializable> disinfectedFileProps = new HashMap<QName, Serializable>();
			disinfectedFileProps.put(AntivirusModel.PROP_INFECTED_CLEAN,false);
			nodeService.addAspect(actionedUponNodeRef, AntivirusModel.ASPECT_INFECTED, disinfectedFileProps);
		}
	}
	
}
