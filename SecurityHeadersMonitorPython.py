from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component, BorderLayout, FlowLayout, Dimension, Color
from java.awt.event import ActionListener
from java.io import PrintWriter, File
from java.util import ArrayList
from java.util import List
from java.util import HashSet
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import SwingUtilities
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import Box
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.filechooser import FileNameExtensionFilter
from threading import Lock
import csv
import os
from datetime import datetime

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    # Default security headers to monitor
    DEFAULT_SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options", 
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-Permitted-Cross-Domain-Policies",
        "Referrer-Policy",
        "Clear-Site-Data",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Permissions-Policy",
        "Cache-Control"
    ]
    
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # Set our extension name
        callbacks.setExtensionName("Security Headers Monitor")
        
        # Initialize configurable headers with defaults
        self._security_headers = list(self.DEFAULT_SECURITY_HEADERS)
        
        # Create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        # self._processed_urls = HashSet()  # No deduplication: log every in-scope request
        
        # Set up the UI
        SwingUtilities.invokeLater(lambda: self._create_ui())
        
        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # Process existing proxy history
        SwingUtilities.invokeLater(lambda: self._process_proxy_history())
        
        return
    
    def _create_ui(self):
        # Main panel
        main_panel = JPanel(BorderLayout())
        
        # Configuration panel
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        config_panel.add(JLabel("Headers to monitor (comma-separated):"))
        
        # Text field for configurable headers
        self._headers_field = JTextField(",".join(self._security_headers), 80)
        self._headers_field.setPreferredSize(Dimension(600, 25))
        config_panel.add(self._headers_field)
        
        # Update button
        update_button = JButton("Update Headers", actionPerformed=self._update_headers)
        config_panel.add(update_button)
        
        # Control panel with export buttons
        control_panel = JPanel(FlowLayout())
        
        # Export buttons
        export_csv_button = JButton("Export CSV", actionPerformed=self._export_csv)
        export_asciidoc_button = JButton("Export AsciiDoc", actionPerformed=self._export_asciidoc)
        clear_button = JButton("Clear", actionPerformed=self._clear_log)
        
        control_panel.add(export_csv_button)
        control_panel.add(export_asciidoc_button)
        control_panel.add(clear_button)
        
        # Combine config and control panels
        top_panel = JPanel(BorderLayout())
        top_panel.add(config_panel, BorderLayout.NORTH)
        top_panel.add(control_panel, BorderLayout.SOUTH)
        
        # Main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Table of log entries
        self._logTable = Table(self)
        scrollPane = JScrollPane(self._logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # Tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # Add components to main panel
        main_panel.add(top_panel, BorderLayout.NORTH)
        main_panel.add(self._splitpane, BorderLayout.CENTER)
        
        # Customize our UI components
        self._callbacks.customizeUiComponent(main_panel)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self._logTable)
        self._callbacks.customizeUiComponent(scrollPane)
        self._callbacks.customizeUiComponent(tabs)
        self._callbacks.customizeUiComponent(top_panel)
        self._callbacks.customizeUiComponent(config_panel)
        self._callbacks.customizeUiComponent(control_panel)
        
        # Store main panel reference
        self._main_panel = main_panel
        
        # Add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)
    
    def _update_headers(self, event):
        """Update the monitored headers based on user input"""
        try:
            # Parse the comma-separated headers
            headers_text = self._headers_field.getText().strip()
            if not headers_text:
                JOptionPane.showMessageDialog(self._main_panel, 
                    "Please enter at least one header name.", 
                    "Invalid Input", 
                    JOptionPane.WARNING_MESSAGE)
                return
            
            # Split and clean headers
            new_headers = []
            for header in headers_text.split(","):
                header = header.strip()
                if header:  # Skip empty strings
                    new_headers.append(header)
            
            if not new_headers:
                JOptionPane.showMessageDialog(self._main_panel, 
                    "Please enter at least one valid header name.", 
                    "Invalid Input", 
                    JOptionPane.WARNING_MESSAGE)
                return
            
            # Update the headers list
            self._security_headers = new_headers
            
            # Clear existing data and reprocess
            self._lock.acquire()
            try:
                old_size = self._log.size()
                self._log.clear()
                self._processed_urls.clear()
                if old_size > 0:
                    self.fireTableStructureChanged()
            finally:
                self._lock.release()
            
            # Reprocess proxy history with new headers
            SwingUtilities.invokeLater(lambda: self._process_proxy_history())
            
            JOptionPane.showMessageDialog(self._main_panel, 
                "Headers updated successfully! Processing proxy history...", 
                "Headers Updated", 
                JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._main_panel, 
                "Error updating headers: " + str(e), 
                "Update Error", 
                JOptionPane.ERROR_MESSAGE)
    
    def _process_proxy_history(self):
        """Process all existing proxy history entries"""
        try:
            # Get all proxy history items
            proxy_history = self._callbacks.getProxyHistory()
            
            if proxy_history is None:
                return
            
            processed_count = 0
            
            for index, item in enumerate(proxy_history):
                if item is None:
                    continue
                
                # Check if request is in scope
                analyzed_request = self._helpers.analyzeRequest(item)
                url = analyzed_request.getUrl()
                
                if not self._callbacks.isInScope(url):
                    continue
                
                # Get host and URL (no deduplication)
                host = url.getHost()
                url_string = url.toString()
                
                # Parse response headers (if response exists)
                response = item.getResponse()
                security_header_values = {}
                
                if response is not None:
                    analyzed_response = self._helpers.analyzeResponse(response)
                    headers = analyzed_response.getHeaders()
                    
                    # Extract security headers
                    for header in headers:
                        header_parts = header.split(":", 1)
                        if len(header_parts) == 2:
                            header_name = header_parts[0].strip()
                            header_value = header_parts[1].strip()
                            
                            # Check if this is one of our monitored security headers
                            for security_header in self._security_headers:
                                if header_name.lower() == security_header.lower():
                                    security_header_values[security_header] = header_value
                                    break
                
                # Add to log with proxy ID (using index + 1 to match Burp's 1-based numbering)
                # Include entries even if there's no response to show failed requests
                self._lock.acquire()
                try:
                    self._log.add(LogEntry(
                        index + 1,  # Proxy ID
                        host,
                        url_string,
                        security_header_values,
                        self._callbacks.saveBuffersToTempFiles(item) if response is not None else None
                    ))
                    processed_count += 1
                finally:
                    self._lock.release()
            
            # Update the table display
            if processed_count > 0:
                self.fireTableDataChanged()
                
        except Exception as e:
            # Log error but don't prevent extension from loading
            self._callbacks.printError("Error processing proxy history: " + str(e))
    
    def getTabCaption(self):
        return "Security Headers"
    
    def getUiComponent(self):
        return self._main_panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses from in-scope requests
        if messageIsRequest:
            return
        
        # Check if request is in scope
        if not self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            return
        
        # Get URL and host (no deduplication)
        try:
            analyzed_request = self._helpers.analyzeRequest(messageInfo)
            url = analyzed_request.getUrl()
            host = url.getHost()
            url_string = url.toString()
        except Exception as e:
            self._callbacks.printError("Error analyzing request: " + str(e))
            return
        
        try:
            # Parse response headers (if response exists)
            response = messageInfo.getResponse()
            security_header_values = {}
            if response is not None:
                analyzed_response = self._helpers.analyzeResponse(response)
                headers = analyzed_response.getHeaders()
                # Extract security headers
                for header in headers:
                    header_parts = header.split(":", 1)
                    if len(header_parts) == 2:
                        header_name = header_parts[0].strip()
                        header_value = header_parts[1].strip()
                        for security_header in self._security_headers:
                            if header_name.lower() == security_header.lower():
                                security_header_values[security_header] = header_value
                                break
            # Create a new log entry with the message details
            self._lock.acquire()
            try:
                row = self._log.size()
                # Use negative ID for new requests, starting from -1 and going down
                new_request_id = -(row + 1)
                self._log.add(LogEntry(
                    new_request_id,  # Proxy ID (negative for new requests)
                    host,
                    url_string,
                    security_header_values,
                    self._callbacks.saveBuffersToTempFiles(messageInfo) if response is not None else None
                ))
                self.fireTableRowsInserted(row, row)
            finally:
                self._lock.release()
        except Exception as e:
            self._callbacks.printError("Error processing HTTP message: " + str(e))
    
    # Implement AbstractTableModel methods
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3 + len(self._security_headers)  # ID + Host + URL + security headers

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        elif columnIndex == 1:
            return "Host"
        elif columnIndex == 2:
            return "URL"
        else:
            header_index = columnIndex - 3
            if header_index < len(self._security_headers):
                return self._security_headers[header_index]
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if rowIndex >= self._log.size():
            return ""
        
        logEntry = self._log.get(rowIndex)
        
        if columnIndex == 0:
            proxy_id = logEntry._proxy_id
            if proxy_id < 0:
                return "New"  # Display "New" for new requests
            else:
                return str(proxy_id)
        elif columnIndex == 1:
            return logEntry._host
        elif columnIndex == 2:
            # Check if there was no response
            if (logEntry._requestResponse is None or 
                logEntry._requestResponse.getResponse() is None):
                return logEntry._url + " (No Response)"
            return logEntry._url
        else:
            header_index = columnIndex - 3
            if header_index < len(self._security_headers):
                header_name = self._security_headers[header_index]
                # Check if there was no response at all
                if (logEntry._requestResponse is None or 
                    logEntry._requestResponse.getResponse() is None):
                    return "No Response"
                return logEntry._security_headers.get(header_name, "Missing")
        return ""
    
    # Implement IMessageEditorController methods
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()
    
    # Export functionality
    def _export_csv(self, event):
        try:
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Save CSV Export")
            fileChooser.setFileFilter(FileNameExtensionFilter("CSV files", ["csv"]))
            fileChooser.setSelectedFile(File("security_headers_export.csv"))
            
            result = fileChooser.showSaveDialog(self._main_panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = fileChooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # Ensure .csv extension
                if not file_path.lower().endswith('.csv'):
                    file_path += '.csv'
                
                self._write_csv_file(file_path)
                JOptionPane.showMessageDialog(self._main_panel, 
                    "CSV export completed successfully!", 
                    "Export Complete", 
                    JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self._main_panel, 
                "Error exporting CSV: " + str(e), 
                "Export Error", 
                JOptionPane.ERROR_MESSAGE)
    
    def _write_csv_file(self, file_path):
        with open(file_path, 'w') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header row
            header_row = ["ID", "Host", "URL"] + self._security_headers
            writer.writerow(header_row)
            
            # Write data rows
            for i in range(self._log.size()):
                logEntry = self._log.get(i)
                proxy_id = logEntry._proxy_id
                id_value = "New" if proxy_id < 0 else str(proxy_id)
                
                # Check if there was no response
                url_value = logEntry._url
                if (logEntry._requestResponse is None or 
                    logEntry._requestResponse.getResponse() is None):
                    url_value += " (No Response)"
                
                row = [id_value, logEntry._host, url_value]
                
                for header_name in self._security_headers:
                    # Check if there was no response at all
                    if (logEntry._requestResponse is None or 
                        logEntry._requestResponse.getResponse() is None):
                        value = "No Response"
                    else:
                        value = logEntry._security_headers.get(header_name, "Missing")
                    row.append(value)
                
                writer.writerow(row)
    
    def _export_asciidoc(self, event):
        try:
            fileChooser = JFileChooser()
            fileChooser.setDialogTitle("Save AsciiDoc Export")
            fileChooser.setFileFilter(FileNameExtensionFilter("AsciiDoc files", ["adoc", "asciidoc"]))
            fileChooser.setSelectedFile(File("security_headers_export.adoc"))
            
            result = fileChooser.showSaveDialog(self._main_panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = fileChooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # Ensure .adoc extension
                if not file_path.lower().endswith('.adoc') and not file_path.lower().endswith('.asciidoc'):
                    file_path += '.adoc'
                
                self._write_asciidoc_file(file_path)
                JOptionPane.showMessageDialog(self._main_panel, 
                    "AsciiDoc export completed successfully!", 
                    "Export Complete", 
                    JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self._main_panel, 
                "Error exporting AsciiDoc: " + str(e), 
                "Export Error", 
                JOptionPane.ERROR_MESSAGE)
    
    def _write_asciidoc_file(self, file_path):
        with open(file_path, 'w') as f:
            # Write AsciiDoc header
            f.write("= Security Headers Analysis Report\n")
            f.write(":toc:\n")
            f.write(":toc-placement: auto\n\n")
            f.write("Generated on: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
            # Write monitored headers info
            f.write("== Monitored Headers\n\n")
            f.write("This report analyzes the following security headers:\n\n")
            for header in self._security_headers:
                f.write("* `{}`\n".format(header))
            f.write("\n")
            
            # Write table header
            f.write("== Security Headers Summary\n\n")
            f.write("[options=\"header\"]\n")
            f.write("|===\n")
            
            # Column headers
            header_line = "| ID | Host | URL"
            for header_name in self._security_headers:
                header_line += " | " + header_name
            f.write(header_line + "\n")
            
            # Write data rows
            for i in range(self._log.size()):
                logEntry = self._log.get(i)
                proxy_id = logEntry._proxy_id
                id_value = "New" if proxy_id < 0 else str(proxy_id)
                
                # Check if there was no response
                url_value = logEntry._url
                if (logEntry._requestResponse is None or 
                    logEntry._requestResponse.getResponse() is None):
                    url_value += " *(No Response)*"
                
                row_line = "| {} | {} | {}".format(id_value, logEntry._host, url_value)
                
                for header_name in self._security_headers:
                    # Check if there was no response at all
                    if (logEntry._requestResponse is None or 
                        logEntry._requestResponse.getResponse() is None):
                        value = "*No Response*"
                    else:
                        value = logEntry._security_headers.get(header_name, "*Missing*")
                        if value != "*Missing*":
                            value = "`{}`".format(value)  # Format existing values in backticks
                    row_line += " | " + value
                
                f.write(row_line + "\n")
            
            f.write("|===\n\n")
            
            # Add summary section
            f.write("== Analysis Summary\n\n")
            f.write("Total hosts analyzed: {}\n\n".format(self._log.size()))
            
            # Count missing headers
            for header_name in self._security_headers:
                missing_count = 0
                for i in range(self._log.size()):
                    logEntry = self._log.get(i)
                    if header_name not in logEntry._security_headers:
                        missing_count += 1
                
                if missing_count > 0:
                    f.write("* `{}`: Missing from {} host(s)\n".format(header_name, missing_count))
    
    def _clear_log(self, event):
        result = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Are you sure you want to clear all logged data?",
            "Clear Log",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            self._lock.acquire()
            try:
                old_size = self._log.size()
                self._log.clear()
                self._processed_urls.clear()
                if old_size > 0:
                    self.fireTableRowsDeleted(0, old_size - 1)
            finally:
                self._lock.release()

#
# Extend JTable to handle cell selection
#

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.setAutoCreateRowSorter(True)  # Enable sorting
        
        # Set up custom cell renderer for all columns
        self._custom_renderer = SecurityHeadersCellRenderer(extender)
        self._update_renderers()
    
    def _update_renderers(self):
        """Update cell renderers for all columns"""
        # Apply the custom renderer to all columns
        for i in range(self.getColumnCount()):
            column = self.getColumnModel().getColumn(i)
            column.setCellRenderer(self._custom_renderer)
    
    def structureChanged(self, e):
        """Called when table structure changes"""
        JTable.structureChanged(self, e)
        # Update renderers after structure change
        SwingUtilities.invokeLater(lambda: self._update_renderers())
    
    def changeSelection(self, row, col, toggle, extend):
        # Show the log entry for the selected row
        if self._extender._log.size() > 0 and row < self._extender._log.size():
            # Convert view row to model row in case table is sorted
            model_row = self.convertRowIndexToModel(row)
            logEntry = self._extender._log.get(model_row)
            
            if logEntry._requestResponse is not None:
                self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
                self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
                self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)

#
# Class to hold details of each log entry
#

class LogEntry:
    def __init__(self, proxy_id, host, url, security_headers, requestResponse):
        self._proxy_id = proxy_id  # ID from proxy history or negative for new requests
        self._host = host
        self._url = url
        self._security_headers = security_headers  # Dictionary of header name -> value
        self._requestResponse = requestResponse

#
# Custom table cell renderer for highlighting missing headers and no response cases
#

class SecurityHeadersCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        DefaultTableCellRenderer.__init__(self)
        self._extender = extender
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        
        # Reset to default colors first
        if not isSelected:
            component.setBackground(Color.WHITE)
            component.setForeground(Color.BLACK)
        
        # Only apply custom coloring if not selected
        if not isSelected and row < self._extender._log.size():
            # Convert view row to model row in case table is sorted
            model_row = table.convertRowIndexToModel(row)
            logEntry = self._extender._log.get(model_row)
            
            # Check if this is a security header column (columns 3 and beyond)
            if column >= 3:
                header_index = column - 3
                if header_index < len(self._extender._security_headers):
                    header_name = self._extender._security_headers[header_index]
                    
                    # Check if header is missing, if there was no response, or if value is "No Response"
                    if (header_name not in logEntry._security_headers or 
                        logEntry._requestResponse is None or 
                        logEntry._requestResponse.getResponse() is None or
                        str(value) == "No Response"):
                        component.setBackground(Color.RED)
                        component.setForeground(Color.WHITE)
                    # Also check for "Missing" text value
                    elif str(value) == "Missing":
                        component.setBackground(Color.RED)
                        component.setForeground(Color.WHITE)
            
            # Check if URL column and there was no response or contains "(No Response)"
            elif column == 2:  # URL column
                if (logEntry._requestResponse is None or 
                    logEntry._requestResponse.getResponse() is None or
                    "(No Response)" in str(value)):
                    component.setBackground(Color.RED)
                    component.setForeground(Color.WHITE)
        
        return component
