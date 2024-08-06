#pragma once
#include <fstream>
#include <string>
#include <vector>
#include <map>

class XMLParser;
class XMLElement;
class XMLAttribute;


class XMLParser
{
public:
    XMLParser();

    void startReadingFile();

    void parseXMLStr(const std::string& xml_string);

    std::vector<XMLElement> readChildElement(const std::string& name_element, const XMLElement& root_element);
    std::vector<XMLElement> readElement(const std::string& element_name);
    
    std::vector<XMLElement> getElements(const std::string& element_name);
    
    std::string configureString(const std::string& sender, const std::string& recipient, const std::string& content, const std::string& timestamp);

    void Clear() 
    {
        _elements.clear();
        _full_file.clear();
    }
private:
    std::string _file_name;
    
    std::vector<std::string> _full_file;
    std::vector<XMLElement> _elements;
};

class XMLElement
{
public:
    XMLElement(const std::string& name, const std::string& element_line, const size_t start_index, const size_t end_index);

    size_t getStart() const { return _start_line_id; }
    size_t getEnd() const { return _end_line_id; }
    std::string getLine() const { return _element_line; }
    std::string getName() const { return _name; }

    XMLAttribute readAttribute(const std::string& attribute_name);
    XMLAttribute getAttribute(const std::string& attribute_name);
    
    XMLAttribute createAttribute(const std::string& attribute_name, const std::string& attribute_data = "");
private:
    std::string _name;
    size_t _start_line_id, _end_line_id;
    std::string _element_line;

    std::map<std::string, XMLAttribute> attribute_map;
};

class XMLAttribute
{
public:
    XMLAttribute(const std::string& attribute);
    XMLAttribute() { _attribute_data = ""; }

    std::string getData() const { return _attribute_data; }

    void storeData(const std::string& attribute_data) { _attribute_data = attribute_data; }
private:
    std::string _attribute_data;
};