CULTURE = ko-kr
LANG_FILE = ko_KR.wxl
TARGET = CertMan-ko.msi

ifeq (${MAKECMDGOALS}, en)
	CULTURE = en-us
	LANG_FILE = en_US.wxl
	TARGET = CertMan-en.msi
endif
ifeq (${MAKECMDGOALS}, ko)
	CULTURE = ko-kr
	LANG_FILE = ko_KR.wxl
	TARGET = CertMan-ko.msi
endif

all: $(TARGET)
en: all
ko: all

CC=/d/bin/wix/candle.exe
LD=/d/bin/wix/light.exe
PARAFFIN=/d/bin/Paraffin/Paraffin.exe

CFLAGS = -ext WixUIExtension -ext WixUtilExtension
LDFLAGS = -spdb -ext WixUIExtension -ext WixUtilExtension \
		-loc ${LANG_FILE} -cultures:${CULTURE} -sice:ICE80

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs fragment.wxs CertMan.wxs

OBJECTS = ${sources:%.wxs=%.wixobj}

fragment.wxs:
	$(PARAFFIN) -dir ./CertMan -gn group_bin -alias bin fragment.wxs
	cp -rf ./CertMan/* ./bin

%.wixobj : %.wxs
	$(CC) -arch x64 $(CFLAGS) $< -o $@
#	$(CC) $(CFLAGS) $< -o $@

CertMan.wixobj : CertMan.wxs Includes.wxi
	$(CC) $(CFLAGS) $< -o $@

$(TARGET) : $(OBJECTS) $(LANG_FILE)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

clean :
	rm -f $(OBJECTS) *.msi fragment.*

rmbin :
	rm -f *.msi *.wixobj

.PHONY: all en ko clean
