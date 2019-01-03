# This Autopsy Python module will perform basic parsing of the ProtonMail
# database and attempts to extract as much clear text data as possible.
#
# Note: Much of the data within ProtonMail is encrypted so you
# may want to analyze the 'proton.db'  manually.  Also, this module, like
# most things I write, is not 100% complete!  :\
#
# Contact: Derrick Karpo [dkarpo <at> gmail [dot] com]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import os
import jarray
import inspect
from java.io import File
from java.lang import Class
from java.util.logging import Level
from java.sql import DriverManager
from java.sql import SQLException
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ProtonMailDataSourceIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "ProtonMail"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parse the ProtonMail SQLite database"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProtonMailDataSourceIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class ProtonMailDataSourceIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(ProtonMailDataSourceIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # setup code
    def startUp(self, context):
        self.context = context
        pass

    # parsing stage
    def process(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # create new artifacts
        skCase = Case.getCurrentCase().getSleuthkitCase();
        skCase_Tran = skCase.beginTransaction()
        try:
            self.log(Level.INFO, "Creating New Artifacts")
            artPMContact = skCase.addArtifactType( "TSK_PM_CONTACT", "ProtonMail Contact")
            artPMContactData = skCase.addArtifactType( "TSK_PM_CONTACTDATA", "ProtonMail Contact Data")
            artPMContactEmails = skCase.addArtifactType( "TSK_PM_CONTACTEMAILS", "ProtonMail Contact Emails")
            artPMContactLabel = skCase.addArtifactType( "TSK_PM_CONTACTLABEL", "ProtonMail User Labels")
            artPMContactMessage = skCase.addArtifactType( "TSK_PM_CONTACTMESSAGE", "ProtonMail Messages")
            artPMContactNotification = skCase.addArtifactType( "TSK_PM_CONTACTNOTIFICATION", "ProtonMail Notifications")
        except:
            self.log(Level.INFO, "Artifact Creation failed.  They may already exist.")
            artPMContact = skCase.getArtifactTypeID("TSK_PM_CONTACT")
            artPMContactData = skCase.getArtifactTypeID("TSK_PM_CONTACTDATA")
            artPMContactEmails = skCase.getArtifactTypeID("TSK_PM_CONTACTEMAILS")
            artPMContactLabel = skCase.getArtifactTypeID("TSK_PM_CONTACTLABEL")
            artPMContactMessage = skCase.getArtifactTypeID("TSK_PM_CONTACTMESSAGE")
            artPMContactNotification = skCase.getArtifactTypeID("TSK_PM_CONTACTNOTIFICATION")

        # create new attributes
        try:
            #
            # 'contact' table attributes
            #
            attPMContactName = skCase.addArtifactAttributeType("TSK_PM_CONTACT_NAME",
                                                               BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                               "Name")
            attPMContactCreateTime = skCase.addArtifactAttributeType("TSK_PM_CONTACT_CREATETIME",
                                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                                     "Create Time")
            attPMContactModifyTime = skCase.addArtifactAttributeType("TSK_PM_CONTACT_MODIFYTIME",
                                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                                     "Modify Time")
            #
            # 'contact_data' table attributes
            #
            attPMContactDataName = skCase.addArtifactAttributeType("TSK_PM_CONTACTDATA_NAME",
                                                                   BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                   "Name")
            attPMContactDataPrimaryEmail = skCase.addArtifactAttributeType("TSK_PM_CONTACTDATA_PRIMARYEMAIL",
                                                                           BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                           "Primary Email")
            #
            # 'contact_emails' table attributes
            #
            attPMContactEmailsName = skCase.addArtifactAttributeType("TSK_PM_CONTACTEMAILS_NAME",
                                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                     "Name")
            attPMContactEmailsEmail = skCase.addArtifactAttributeType("TSK_PM_CONTACTEMAILS_EMAIL",
                                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                      "Email")
            #
            # 'label' table attributes
            #
            attPMContactLabelName = skCase.addArtifactAttributeType("TSK_PM_CONTACTLABEL_NAME",
                                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                    "Name")
            attPMContactLabelColor = skCase.addArtifactAttributeType("TSK_PM_CONTACTLABEL_COLOR",
                                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                     "Color")
            #
            # 'message' table attributes
            #
            attPMContactMessageBCCList = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_BCCLIST",
                                                                         BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                         "BCC List")
            attPMContactMessageBody = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_BODY",
                                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                      "Body")
            attPMContactMessageCCList = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_CCLIST",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "CC List")
            attPMContactMessageHeader = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_HEADER",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "Header")
            attPMContactMessageIsDownloaded = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISDOWNLOADED",
                                                                              BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                              "Is Downloaded?")
            attPMContactMessageIsEncrypted = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISENCRYPTED",
                                                                             BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                             "Is Encrypted?")
            attPMContactMessageIsForwarded = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISFORWARDED",
                                                                             BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                             "Is Forwarded?")
            attPMContactMessageIsRead = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISREAD",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "Is Read?")
            attPMContactMessageIsReplied = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISREPLIED",
                                                                           BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                           "Is Replied?")
            attPMContactMessageIsRepliedAll = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_ISREPLIEDALL",
                                                                              BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                              "Is Replied All?")
            attPMContactMessageReplyTo = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_REPLYTO",
                                                                         BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                         "Reply To")
            attPMContactMessageSenderAddress = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_SENDERADDRESS",
                                                                               BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                               "Sender Address")
            attPMContactMessageSenderName = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_SENDERNAME",
                                                                            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                            "From")
            attPMContactMessageTotalSize = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_TOTALSIZE",
                                                                           BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                           "Total Size")
            attPMContactMessageSpamScore = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_SPAMSCORE",
                                                                           BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                           "Spam Score")
            attPMContactMessageStarred = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_STARRED",
                                                                         BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                         "Starred")
            attPMContactMessageSubject = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_SUBJECT",
                                                                         BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                         "Subject")
            attPMContactMessageTime = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_TIME",
                                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                                      "Time")
            attPMContactMessageTo = skCase.addArtifactAttributeType("TSK_PM_CONTACTMESSAGE_TO",
                                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                    "To")

            #
            # 'notification' table attributes
            #
            attPMContactNotificationNotificationBody = skCase.addArtifactAttributeType("TSK_PM_CONTACTNOTIFICATION_NOTIFICATIONBODY",
                                                                                       BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                                       "Notification Body")
            attPMContactNotificationNotificationTitle = skCase.addArtifactAttributeType("TSK_PM_CONTACTNOTIFICATION_NOTIFICATIONTITLE",
                                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                                        "Notification Title")
        except:
            self.log(Level.INFO, "Attributes Creation Error.")


        # for message posting
        PostBoard=IngestServices.getInstance()

        # use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # find all "proton.db" files
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "proton.db")

        # count the number of files, start processing, and write it out to the message board
        # to the "Ingest inbox".
        numFiles = len(files)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA,
            "ProtonMail",
            "Starting to analyze " + str(numFiles) + " file(s)")
        PostBoard.postMessage(message)

        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in files:
            # check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # start processing
            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # this is a comment, I like comments
            progressBar.progress(fileCount)
            progressBar.progress("ProtonMail")

            # try load up the SQLite database
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(),
                                     str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
            binary_file = open(lclDbPath, "rb")
            data = binary_file.read(15)
            binary_file.close()
            if str(data) == "SQLite format 3":
                try:
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s" % lclDbPath)
                except SQLException as e:
                    message = IngestMessage.createMessage(
                        IngestMessage.MessageType.DATA,
                        "ProtonMail",
                        "Failed to open " + file.getName()+ " as SQLite",
                        str(msgcounter))
                    IngestServices.getInstance().postMessage(message)

                # query the tables in the database then jam the results into the attributes
                try:
                    sqlQuery = dbConn.createStatement()

                    try:
                        # get the attributes for the 'contact' table
                        attPMContactName = skCase.getAttributeType("TSK_PM_CONTACT_NAME")
                        attPMContactCreateTime = skCase.getAttributeType("TSK_PM_CONTACT_CREATETIME")
                        attPMContactModifyTime = skCase.getAttributeType("TSK_PM_CONTACT_MODIFYTIME")
                        # process the 'contact' table
                        queryContact = sqlQuery.executeQuery("select CreateTime, ModifyTime, Name from contact;")
                        while queryContact.next():
                            art = file.newArtifact(artPMContact)
                            art.addAttribute(BlackboardAttribute(attPMContactName, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContact.getString("Name")))
                            art.addAttribute(BlackboardAttribute(attPMContactCreateTime, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContact.getInt("CreateTime")))
                            art.addAttribute(BlackboardAttribute(attPMContactModifyTime, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContact.getInt("ModifyTime")))

                        # get the attributes for the 'contact_data' table
                        attPMContactDataName = skCase.getAttributeType("TSK_PM_CONTACTDATA_NAME")
                        attPMContactDataPrimaryEmail = skCase.getAttributeType("TSK_PM_CONTACTDATA_PRIMARYEMAIL")
                        # process the 'contact_data' table
                        queryContactData = sqlQuery.executeQuery("select Name, PrimaryEMail from contact_data;")
                        while queryContactData.next():
                            art = file.newArtifact(artPMContactData)
                            art.addAttribute(BlackboardAttribute(attPMContactDataName, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactData.getString("Name")))
                            art.addAttribute(BlackboardAttribute(attPMContactDataPrimaryEmail, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactData.getString("PrimaryEmail")))


                        # get the attributes for the 'contact_emails' table
                        attPMContactEmailsName = skCase.getAttributeType("TSK_PM_CONTACTEMAILS_NAME")
                        attPMContactEmailsEmail = skCase.getAttributeType("TSK_PM_CONTACTEMAILS_EMAIL")
                        # process the 'contact_emails' table
                        queryContactEmails = sqlQuery.executeQuery("select Name, Email from contact_emails;")
                        while queryContactEmails.next():
                            art = file.newArtifact(artPMContactEmails)
                            art.addAttribute(BlackboardAttribute(attPMContactEmailsName, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactEmails.getString("Name")))
                            art.addAttribute(BlackboardAttribute(attPMContactEmailsEmail, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactEmails.getString("Email")))

                        # get the attributes for the 'label' table
                        attPMContactLabelName = skCase.getAttributeType("TSK_PM_CONTACTLABEL_NAME")
                        attPMContactLabelColor = skCase.getAttributeType("TSK_PM_CONTACTLABEL_COLOR")
                        # process the 'label' table
                        queryContactLabel = sqlQuery.executeQuery("select Name, Color from label;")
                        while queryContactLabel.next():
                            art = file.newArtifact(artPMContactLabel)
                            art.addAttribute(BlackboardAttribute(attPMContactLabelName, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactEmails.getString("Name")))
                            art.addAttribute(BlackboardAttribute(attPMContactLabelColor, ProtonMailDataSourceIngestModuleFactory.moduleName, queryContactEmails.getString("Color")))

                        # get the attributes for the 'message' table
                        attPMContactMessageBCCList = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_BCCLIST")
                        attPMContactMessageBody = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_BODY")
                        attPMContactMessageCCList = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_CCLIST")
                        attPMContactMessageHeader = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_HEADER")
                        attPMContactMessageIsDownloaded = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISDOWNLOADED")
                        attPMContactMessageIsEncrypted = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISENCRYPTED")
                        attPMContactMessageIsForwarded = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISFORWARDED")
                        attPMContactMessageIsRead = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISREAD")
                        attPMContactMessageIsReplied = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISREPLIED")
                        attPMContactMessageIsRepliedAll = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_ISREPLIEDALL")
                        attPMContactMessageReplyTo = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_REPLYTO")
                        attPMContactMessageSenderAddress = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_SENDERADDRESS")
                        attPMContactMessageSenderName = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_SENDERNAME")
                        attPMContactMessageTotalSize = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_TOTALSIZE")
                        attPMContactMessageSpamScore = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_SPAMSCORE")
                        attPMContactMessageStarred = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_STARRED")
                        attPMContactMessageSubject = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_SUBJECT")
                        attPMContactMessageTime = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_TIME")
                        attPMContactMessageTo = skCase.getAttributeType("TSK_PM_CONTACTMESSAGE_TO")
                        # process the 'message' table
                        queryContactMessage = sqlQuery.executeQuery("select BCCListString, Body, CCListString, Header, IsDownloaded, \
                        IsEncrypted, IsForwarded, IsRead, IsReplied, IsRepliedAll, ReplyTosString, SenderAddress, SenderName, \
                        TotalSize, SpamScore, Starred, Subject, Time, ToListString from message;")
                        while queryContactMessage.next():
                            art = file.newArtifact(artPMContactMessage)
                            bcclist = queryContactMessage.getString("BCCListString")
                            body = queryContactMessage.getString("Body")
                            cclist = queryContactMessage.getString("CCListString")
                            header = queryContactMessage.getString("Header")
                            isdownloaded = queryContactMessage.getString("IsDownloaded")
                            isencrypted = queryContactMessage.getString("IsEncrypted")
                            isforwarded = queryContactMessage.getString("IsForwarded")
                            isread = queryContactMessage.getString("IsRead")
                            isreplied = queryContactMessage.getString("IsReplied")
                            isrepliedall = queryContactMessage.getString("IsRepliedAll")
                            replyto = queryContactMessage.getString("ReplyTosString")
                            senderaddress = queryContactMessage.getString("SenderAddress")
                            sendername = queryContactMessage.getString("SenderName")
                            totalsize = queryContactMessage.getString("TotalSize")
                            spamscore = queryContactMessage.getString("SpamScore")
                            starred = queryContactMessage.getString("Starred")
                            subject = queryContactMessage.getString("Subject")
                            time = queryContactMessage.getInt("Time")
                            to = queryContactMessage.getString("ToListString")
                            art.addAttributes(((BlackboardAttribute(attPMContactMessageTime, ProtonMailDataSourceIngestModuleFactory.moduleName, time)), \
                                               (BlackboardAttribute(attPMContactMessageTo, ProtonMailDataSourceIngestModuleFactory.moduleName, to)), \
                                               (BlackboardAttribute(attPMContactMessageReplyTo, ProtonMailDataSourceIngestModuleFactory.moduleName, replyto)), \
                                               (BlackboardAttribute(attPMContactMessageSenderName, ProtonMailDataSourceIngestModuleFactory.moduleName, sendername)), \
                                               (BlackboardAttribute(attPMContactMessageSenderAddress, ProtonMailDataSourceIngestModuleFactory.moduleName, senderaddress)), \
                                               (BlackboardAttribute(attPMContactMessageSubject, ProtonMailDataSourceIngestModuleFactory.moduleName, subject)), \
                                               (BlackboardAttribute(attPMContactMessageBody, ProtonMailDataSourceIngestModuleFactory.moduleName, body)), \
                                               (BlackboardAttribute(attPMContactMessageHeader, ProtonMailDataSourceIngestModuleFactory.moduleName, header)), \
                                               (BlackboardAttribute(attPMContactMessageTotalSize, ProtonMailDataSourceIngestModuleFactory.moduleName, totalsize)), \
                                               (BlackboardAttribute(attPMContactMessageBCCList, ProtonMailDataSourceIngestModuleFactory.moduleName, bcclist)), \
                                               (BlackboardAttribute(attPMContactMessageCCList, ProtonMailDataSourceIngestModuleFactory.moduleName, cclist)), \
                                               (BlackboardAttribute(attPMContactMessageBody, ProtonMailDataSourceIngestModuleFactory.moduleName, body)), \
                                               (BlackboardAttribute(attPMContactMessageIsDownloaded, ProtonMailDataSourceIngestModuleFactory.moduleName, isdownloaded)), \
                                               (BlackboardAttribute(attPMContactMessageIsEncrypted, ProtonMailDataSourceIngestModuleFactory.moduleName, isencrypted)), \
                                               (BlackboardAttribute(attPMContactMessageIsForwarded, ProtonMailDataSourceIngestModuleFactory.moduleName, isforwarded)), \
                                               (BlackboardAttribute(attPMContactMessageIsRead, ProtonMailDataSourceIngestModuleFactory.moduleName, isread)), \
                                               (BlackboardAttribute(attPMContactMessageIsReplied, ProtonMailDataSourceIngestModuleFactory.moduleName, isreplied)), \
                                               (BlackboardAttribute(attPMContactMessageIsRepliedAll, ProtonMailDataSourceIngestModuleFactory.moduleName, isrepliedall)), \
                                               (BlackboardAttribute(attPMContactMessageSpamScore, ProtonMailDataSourceIngestModuleFactory.moduleName, spamscore))))

                        # get the attributes for the 'notification' table
                        attPMContactNotificationNotificationBody = skCase.getAttributeType("TSK_PM_CONTACTNOTIFICATION_NOTIFICATIONBODY")
                        attPMContactNotificationNotificationTitle = skCase.getAttributeType("TSK_PM_CONTACTNOTIFICATION_NOTIFICATIONTITLE")
                        # process the 'notification' table
                        queryContactNotification = sqlQuery.executeQuery("select notification_body, notification_title from notification;")
                        while queryContactNotification.next():
                            art = file.newArtifact(artPMContactNotification)
                            notification_body = queryContactNotification.getString("notification_body")
                            notification_title = queryContactNotification.getString("notification_title")
                            art.addAttributes(((BlackboardAttribute(attPMContactNotificationNotificationTitle, ProtonMailDataSourceIngestModuleFactory.moduleName, notification_title)), \
                                               (BlackboardAttribute(attPMContactNotificationNotificationBody, ProtonMailDataSourceIngestModuleFactory.moduleName, notification_body))))

                    except SQLException as e:
                        self.log(Level.INFO, "SQL Error: " + e.getMessage())
                except SQLException as e:
                    self.log(Level.INFO, "Error querying database " + file.getName() + " (" + e.getMessage() + ")")

                # all done?
                sqlQuery.close()
                dbConn.close()
                os.remove(lclDbPath)

            # Update the progress bar
            progressBar.progress(fileCount)

        # done processing
        if numFiles == 0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                  "ProtonMail",
                                                  "No files to analyze")
            PostBoard.postMessage(message)
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                  "ProtonMail",
                                                  "Finished to analyze %d file(s)" % fileCount)
            PostBoard.postMessage(message)

        return IngestModule.ProcessResult.OK
